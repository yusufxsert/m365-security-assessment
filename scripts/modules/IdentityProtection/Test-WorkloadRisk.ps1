#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Evaluates security risk from service principals, workload identities, and app permissions.

.DESCRIPTION
    Test-WorkloadRisk checks the tenant's non-human identity surface for:
      - WRI-001  Service principals with risky high-privilege app permissions
      - WRI-002  Unused service principals (no sign-in in 90+ days)
      - WRI-003  Service principals with credentials expiring within 30 days
      - WRI-004  Apps with admin consent for sensitive delegated permissions

    Service principal sign-in activity (WRI-002) requires AuditLog.Read.All.
    All checks gracefully handle insufficient permissions.

.NOTES
    Required Graph Permissions : Application.Read.All, AuditLog.Read.All
    License Required            : E3 (WRI-001, WRI-003, WRI-004); E3+ for WRI-002 sign-in data

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-WorkloadRisk {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Risky application role definitions (appId of Microsoft APIs → role value)
    # These grant tenant-wide access with no user context
    # -------------------------------------------------------------------------
    $highRiskAppRoles = @(
        'Application.ReadWrite.All',
        'AppRoleAssignment.ReadWrite.All',
        'Directory.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory',
        'User.ReadWrite.All',
        'Group.ReadWrite.All',
        'Mail.ReadWrite',           # Application permission (all mailboxes)
        'Files.ReadWrite.All',
        'Sites.ReadWrite.All',
        'TeamSettings.ReadWrite.All',
        'Policy.ReadWrite.ConditionalAccess',
        'PrivilegedAccess.ReadWrite.AzureAD'
    )

    # Sensitive OAuth2 (delegated) permission scopes for WRI-004
    $sensitiveDelegatedScopes = @(
        'Mail.Read',
        'Mail.ReadWrite',
        'Mail.Send',
        'Files.ReadWrite.All',
        'Sites.ReadWrite.All',
        'User.ReadWrite.All',
        'Directory.ReadWrite.All',
        'Application.ReadWrite.All',
        'full_access_as_user',          # EWS full access
        'Contacts.ReadWrite',
        'Calendars.ReadWrite'
    )

    # =========================================================================
    # WRI-001: Service principals with high-risk app role assignments
    # =========================================================================
    try {
        # Retrieve all app role assignments (application permissions granted to SPs)
        $appRoleResponse = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,servicePrincipalType&$top=999' `
            -ErrorAction Stop
        $allSPs = $appRoleResponse.value

        $nextLink = $appRoleResponse.'@odata.nextLink'
        while ($nextLink) {
            $page   = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $allSPs += $page.value
            $nextLink = $page.'@odata.nextLink'
        }

        $riskyApps    = [System.Collections.Generic.List[string]]::new()
        $checkedCount = 0

        foreach ($sp in $allSPs) {
            # Skip Microsoft-owned first-party service principals
            if ($sp.servicePrincipalType -eq 'ManagedIdentity' -or
                $sp.appId -match '^00000') {
                continue
            }

            try {
                $assignmentsResponse = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=100" `
                    -ErrorAction Stop
                $assignments = $assignmentsResponse.value
                $checkedCount++

                foreach ($assignment in $assignments) {
                    # Resolve the role value from the resource SP
                    try {
                        $resourceSP = Invoke-MgGraphRequest -Method GET `
                            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($assignment.resourceId)?`$select=id,displayName,appRoles" `
                            -ErrorAction Stop
                        $roleDefinition = $resourceSP.appRoles | Where-Object { $_.id -eq $assignment.appRoleId }
                        if ($roleDefinition -and $highRiskAppRoles -contains $roleDefinition.value) {
                            $riskyApps.Add("$($sp.displayName) — $($roleDefinition.value) (on $($resourceSP.displayName))")
                        }
                    }
                    catch { Write-Verbose "Could not resolve appRole for $($sp.displayName): $_" }
                }
            }
            catch { Write-Verbose "Could not get assignments for $($sp.displayName): $_" }
        }

        $wri001Status = if ($riskyApps.Count -eq 0) { 'PASS' } else { 'HIGH' }
        $wri001Detail = "Service principals checked: $checkedCount (non-Microsoft). " +
                        "SPs with high-risk application permissions: $($riskyApps.Count)."
        if ($riskyApps.Count -gt 0) {
            $wri001Detail += " Review each app — these permissions allow tenant-wide data access or privilege escalation."
        }
    }
    catch {
        $riskyApps    = @()
        $wri001Status = 'INFO'
        $wri001Detail = "Check skipped: insufficient permissions. Required: Application.Read.All. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'WRI-001' `
        -Category 'IdentityProtection' `
        -Name 'Service Principals with High-Risk Permissions' `
        -Status $wri001Status `
        -Detail $wri001Detail `
        -Recommendation 'Review and reduce permissions for each listed service principal. Replace broad permissions (e.g. Directory.ReadWrite.All) with scoped alternatives. Revoke unused app role assignments.' `
        -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions' `
        -CISControl '' `
        -SC300Domain 'Workload Identity Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @($riskyApps)))

    # =========================================================================
    # WRI-002: Stale service principals (no sign-in in 90+ days)
    # =========================================================================
    try {
        $cutoffDate = (Get-Date).AddDays(-90).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

        # signInActivity requires AuditLog.Read.All; not available on all SP types
        $staleSPResponse = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName,appId,servicePrincipalType,signInActivity&`$top=999" `
            -ErrorAction Stop
        $spWithActivity = $staleSPResponse.value

        $nextLink = $staleSPResponse.'@odata.nextLink'
        while ($nextLink) {
            $page           = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $spWithActivity += $page.value
            $nextLink       = $page.'@odata.nextLink'
        }

        $staleSPs = @($spWithActivity | Where-Object {
            $sp = $_
            # Skip Microsoft first-party and managed identities for noise reduction
            $sp.servicePrincipalType -notin @('ManagedIdentity') -and
            $sp.appId -notmatch '^00000' -and
            (
                # No sign-in data at all OR last sign-in older than 90 days
                -not $sp.signInActivity -or
                -not $sp.signInActivity.lastSignInDateTime -or
                [datetime]$sp.signInActivity.lastSignInDateTime -lt [datetime]$cutoffDate
            )
        })

        $wri002Status    = if ($staleSPs.Count -eq 0) { 'PASS' }
                           elseif ($staleSPs.Count -le 10) { 'MEDIUM' }
                           else { 'MEDIUM' }
        $staleSpNames    = @($staleSPs | ForEach-Object {
            $lastSignIn = if ($_.signInActivity.lastSignInDateTime) { $_.signInActivity.lastSignInDateTime } else { 'Never' }
            "$($_.displayName) (last sign-in: $lastSignIn)"
        })
        $wri002Detail    = "Non-Microsoft service principals with no sign-in in 90+ days (or never): $($staleSPs.Count) of $($spWithActivity.Count) total."
        if ($staleSPs.Count -gt 0) {
            $wri002Detail += " Stale SPs with active credentials expand the attack surface unnecessarily."
        }
    }
    catch {
        $staleSpNames = @()
        $wri002Status = 'INFO'
        $wri002Detail = "Check skipped: insufficient permissions. Required: Application.Read.All + AuditLog.Read.All. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'WRI-002' `
        -Category 'IdentityProtection' `
        -Name 'Stale Service Principals (90+ Days Inactive)' `
        -Status $wri002Status `
        -Detail $wri002Detail `
        -Recommendation 'Review and disable or delete service principals with no recent sign-in. Verify with application owners before deletion. Revoke credentials on disabled SPs.' `
        -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/application-sign-in-problem-application-error' `
        -CISControl '' `
        -SC300Domain 'Workload Identity Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects $staleSpNames))

    # =========================================================================
    # WRI-003: Service principals with credentials expiring within 30 days
    # =========================================================================
    try {
        $expiryThreshold = (Get-Date).AddDays(30).ToUniversalTime()
        $today           = (Get-Date).ToUniversalTime()

        # Re-use allSPs from WRI-001 if available, otherwise re-fetch
        if (-not $allSPs) {
            $spListResponse = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,servicePrincipalType,passwordCredentials,keyCredentials&$top=999' `
                -ErrorAction Stop
            $allSPs = $spListResponse.value

            $nextLink = $spListResponse.'@odata.nextLink'
            while ($nextLink) {
                $page   = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
                $allSPs += $page.value
                $nextLink = $page.'@odata.nextLink'
            }
        }

        $expiringCreds = [System.Collections.Generic.List[string]]::new()

        foreach ($sp in $allSPs) {
            if ($sp.servicePrincipalType -eq 'ManagedIdentity') { continue }

            # Check password credentials (client secrets)
            foreach ($cred in @($sp.passwordCredentials)) {
                if (-not $cred.endDateTime) { continue }
                $expiry = [datetime]$cred.endDateTime
                if ($expiry -gt $today -and $expiry -le $expiryThreshold) {
                    $daysLeft = [int]($expiry - $today).TotalDays
                    $expiringCreds.Add("$($sp.displayName) — Secret '$($cred.displayName)' expires in $daysLeft days ($($cred.endDateTime))")
                }
            }

            # Check key credentials (certificates)
            foreach ($cred in @($sp.keyCredentials)) {
                if (-not $cred.endDateTime) { continue }
                $expiry = [datetime]$cred.endDateTime
                if ($expiry -gt $today -and $expiry -le $expiryThreshold) {
                    $daysLeft = [int]($expiry - $today).TotalDays
                    $expiringCreds.Add("$($sp.displayName) — Certificate '$($cred.displayName)' expires in $daysLeft days ($($cred.endDateTime))")
                }
            }
        }

        $wri003Status = if ($expiringCreds.Count -eq 0) { 'PASS' }
                        elseif ($expiringCreds.Count -le 5) { 'MEDIUM' }
                        else { 'MEDIUM' }
        $wri003Detail = "Service principal credentials (secrets + certificates) expiring within 30 days: $($expiringCreds.Count)."
        if ($expiringCreds.Count -gt 0) {
            $wri003Detail += " Expired credentials cause application outages and may force emergency rotations."
        }
    }
    catch {
        $expiringCreds = @()
        $wri003Status  = 'INFO'
        $wri003Detail  = "Check skipped: insufficient permissions. Required: Application.Read.All. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'WRI-003' `
        -Category 'IdentityProtection' `
        -Name 'Service Principal Credentials Expiring (30 Days)' `
        -Status $wri003Status `
        -Detail $wri003Detail `
        -Recommendation 'Rotate credentials for all listed service principals before expiry. Consider migrating to Managed Identities or federated credentials to eliminate secret rotation entirely.' `
        -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/howto-create-service-principal-portal' `
        -CISControl '' `
        -SC300Domain 'Workload Identity Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @($expiringCreds)))

    # =========================================================================
    # WRI-004: Apps with admin consent for sensitive delegated permissions
    # =========================================================================
    try {
        # oauth2PermissionGrants returns delegated permission grants
        $grantResponse = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' `
            -ErrorAction Stop
        $grants = $grantResponse.value

        $nextLink = $grantResponse.'@odata.nextLink'
        while ($nextLink) {
            $page   = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $grants += $page.value
            $nextLink = $page.'@odata.nextLink'
        }

        # Filter to admin-consented grants (consentType = AllPrincipals = tenant-wide)
        $adminConsentGrants = @($grants | Where-Object { $_.consentType -eq 'AllPrincipals' })

        $sensitiveGrants = [System.Collections.Generic.List[string]]::new()

        foreach ($grant in $adminConsentGrants) {
            $scopes = $grant.scope -split ' ' | Where-Object { $_ }
            $matchedScopes = $scopes | Where-Object { $sensitiveDelegatedScopes -contains $_ }

            if ($matchedScopes.Count -gt 0) {
                # Resolve the client SP display name
                try {
                    $clientSP = Invoke-MgGraphRequest -Method GET `
                        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.clientId)?`$select=displayName" `
                        -ErrorAction Stop
                    $clientName = $clientSP.displayName
                }
                catch { $clientName = $grant.clientId }

                $sensitiveGrants.Add("$clientName — $($matchedScopes -join ', ')")
            }
        }

        $wri004Status = if ($sensitiveGrants.Count -eq 0) { 'PASS' } else { 'HIGH' }
        $wri004Detail = "Admin-consented delegated permission grants: $($adminConsentGrants.Count) total. " +
                        "Grants with sensitive scopes: $($sensitiveGrants.Count)."
        if ($sensitiveGrants.Count -gt 0) {
            $wri004Detail += " These apps can read/write data on behalf of any user in the tenant."
        }
    }
    catch {
        $sensitiveGrants = @()
        $wri004Status    = 'INFO'
        $wri004Detail    = "Check skipped: insufficient permissions. Required: Application.Read.All + DelegatedPermissionGrant.Read.All. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'WRI-004' `
        -Category 'IdentityProtection' `
        -Name 'Apps with Admin Consent for Sensitive Permissions' `
        -Status $wri004Status `
        -Detail $wri004Detail `
        -Recommendation 'Review each listed app and revoke admin consent for unnecessary sensitive scopes. Enable user consent settings to require admin approval for sensitive permissions. Implement app consent policies.' `
        -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
        -CISControl '' `
        -SC300Domain 'Workload Identity Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @($sensitiveGrants)))

    return $results
}
