#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits enterprise applications (service principals) for access control and permission risks.

.DESCRIPTION
    Test-EnterpriseApps evaluates the tenant's enterprise app (service principal) estate:
    user assignment requirement, tenant-wide admin-consented permissions, application-type
    permissions on sensitive resources, third-party app ratio, inactive apps with consented
    access, and SCIM provisioning coverage.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

.NOTES
    Required Graph Permissions : Application.Read.All, AuditLog.Read.All
    License Required            : E3 minimum; sign-in activity data requires E3+
    Module                      : Microsoft.Graph.Authentication (uses Invoke-MgGraphRequest)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        ENT-001  Enterprise apps with user assignment NOT required
        ENT-002  Tenant-wide admin-consented delegated permissions (AllPrincipals)
        ENT-003  Enterprise apps with sensitive application permissions
        ENT-004  Third-party vs first-party app ratio (risk surface indicator)
        ENT-005  Inactive enterprise apps with admin-consented permissions
        ENT-006  SCIM provisioning configured (positive indicator)
#>

function Test-EnterpriseApps {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Microsoft's tenant ID — used to distinguish first-party apps
    $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'

    # -------------------------------------------------------------------------
    # Retrieve service principals (enterprise apps), enabled only
    # -------------------------------------------------------------------------
    $sps = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $spUri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter=accountEnabled eq true&$select=id,displayName,appId,appOwnerOrganizationId,appRoleAssignmentRequired,servicePrincipalType,signInAudience&$top=999'
        do {
            $spResponse = Invoke-MgGraphRequest -Method GET -Uri $spUri -ErrorAction Stop
            foreach ($sp in $spResponse.value) { $sps.Add($sp) }
            $spUri = $spResponse.'@odata.nextLink'
        } while ($spUri)
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-000' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # ENT-001: Enterprise apps with user assignment NOT required (high-perm apps)
    # -------------------------------------------------------------------------
    # Sensitive application permission GUIDs (static, tenant-agnostic)
    $sensitiveAppRoles = @(
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',  # Application.ReadWrite.All
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7',  # Directory.ReadWrite.All
        'e2a3a72e-5f79-4c64-b1b1-878b674786c9',  # Mail.ReadWrite
        'b633e1c5-b582-4048-a93e-9f11b44c7e96',  # Mail.Send
        '741f803b-c850-494e-b5df-cde7c675a1ca',  # User.ReadWrite.All
        '5b567255-7703-4780-807c-7be8301ae99b',  # Group.ReadWrite.All
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'   # RoleManagement.ReadWrite.Directory
    )

    $noAssignmentApps = [System.Collections.Generic.List[string]]::new()

    foreach ($sp in $sps) {
        # Skip apps that already require user assignment
        if ($sp.appRoleAssignmentRequired -eq $true) { continue }
        # Only flag non-Microsoft apps with potentially sensitive permissions
        if ($sp.appOwnerOrganizationId -eq $microsoftTenantId) { continue }

        # Check if this SP has any sensitive app role assignments
        try {
            $rolesResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=100" `
                -ErrorAction Stop
            $hasSensitive = $rolesResp.value | Where-Object { $_.appRoleId -in $sensitiveAppRoles }
            if ($hasSensitive) {
                $noAssignmentApps.Add($sp.displayName)
            }
        }
        catch {
            Write-Verbose "ENT-001: Could not check app role assignments for $($sp.displayName): $_"
        }
    }

    if ($noAssignmentApps.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-001' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App: User Assignment Not Required (High-Perm Apps)' `
            -Status 'HIGH' `
            -Detail "Found $($noAssignmentApps.Count) enterprise app(s) with sensitive API permissions where 'User assignment required' is disabled. Any user in the tenant can access or trigger these apps without explicit approval." `
            -Recommendation "Enable 'User assignment required' on all enterprise apps with privileged permissions. Under Properties, set 'Assignment required' to Yes, then assign only necessary users/groups." `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/assign-user-or-group-access-portal' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $noAssignmentApps.ToArray()))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-001' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App: User Assignment Requirement' `
            -Status 'PASS' `
            -Detail 'All detected high-permission enterprise apps have user assignment required or are first-party Microsoft apps.' `
            -Recommendation "Periodically review new enterprise apps to ensure 'User assignment required' is enabled for sensitive applications." `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/assign-user-or-group-access-portal' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ENT-002: Tenant-wide (AllPrincipals) admin-consented delegated permissions
    # -------------------------------------------------------------------------
    $sensitiveDelegatedScopes = @(
        'Mail.ReadWrite', 'Mail.Read', 'Mail.Send',
        'Files.ReadWrite.All', 'Files.Read.All',
        'Contacts.ReadWrite', 'Contacts.Read',
        'Calendars.ReadWrite', 'Calendars.Read',
        'User.ReadWrite.All', 'Directory.ReadWrite.All',
        'MailboxSettings.ReadWrite', 'Chat.Read', 'ChannelMessage.Read.All'
    )

    try {
        $grantsUri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=consentType eq ''AllPrincipals''&$top=999'
        $allGrants = [System.Collections.Generic.List[hashtable]]::new()
        do {
            $grantsResp = Invoke-MgGraphRequest -Method GET -Uri $grantsUri -ErrorAction Stop
            foreach ($g in $grantsResp.value) { $allGrants.Add($g) }
            $grantsUri = $grantsResp.'@odata.nextLink'
        } while ($grantsUri)

        $sensitiveGrants = [System.Collections.Generic.List[string]]::new()
        foreach ($grant in $allGrants) {
            $scopes = $grant.scope -split ' '
            $matched = $scopes | Where-Object { $_ -in $sensitiveDelegatedScopes }
            if ($matched) {
                # Resolve SP display name
                $spName = ($sps | Where-Object { $_.id -eq $grant.clientId } | Select-Object -First 1).displayName
                if (-not $spName) { $spName = $grant.clientId }
                $sensitiveGrants.Add("$spName [scopes: $($matched -join ', ')]")
            }
        }

        if ($sensitiveGrants.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'ENT-002' `
                -Category 'WorkloadIdentities' `
                -Name 'Enterprise App: Tenant-Wide Consent for Sensitive Delegated Permissions' `
                -Status 'HIGH' `
                -Detail "Found $($sensitiveGrants.Count) tenant-wide consent grant(s) for sensitive delegated permissions. AllPrincipals consent means every user in the tenant can delegate these permissions to the app without individual consent prompts." `
                -Recommendation 'Review each grant. Revoke consents no longer required. Restrict future consents to user-specific grants. Enable admin consent workflow to require approval for new grants.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
                -CISControl 'CIS M365 1.6' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects $sensitiveGrants.ToArray()))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'ENT-002' `
                -Category 'WorkloadIdentities' `
                -Name 'Enterprise App: Tenant-Wide Sensitive Delegated Permissions' `
                -Status 'PASS' `
                -Detail "No tenant-wide (AllPrincipals) consents found for sensitive scopes. Total AllPrincipals grants in tenant: $($allGrants.Count)." `
                -Recommendation 'Continue auditing consent grants quarterly. Enable the admin consent workflow to prevent uncontrolled consents.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
                -CISControl 'CIS M365 1.6' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-002' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App: Tenant-Wide Consent Grants' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant the required permissions and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ENT-003: Enterprise apps with sensitive application permissions (background)
    # -------------------------------------------------------------------------
    $sensitiveAppRoleMap = @{
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = 'Application.ReadWrite.All'
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = 'Directory.ReadWrite.All'
        'e2a3a72e-5f79-4c64-b1b1-878b674786c9' = 'Mail.ReadWrite'
        'b633e1c5-b582-4048-a93e-9f11b44c7e96' = 'Mail.Send'
        '741f803b-c850-494e-b5df-cde7c675a1ca' = 'User.ReadWrite.All'
        '5b567255-7703-4780-807c-7be8301ae99b' = 'Group.ReadWrite.All'
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = 'RoleManagement.ReadWrite.Directory'
        '810c84a8-4a9e-49e6-bf7d-12d183f40d01' = 'Mail.Read'
        '75359482-378d-4052-8f01-80520e7db3cd' = 'Files.ReadWrite.All'
    }

    $sensitiveAppPermApps = [System.Collections.Generic.List[string]]::new()
    # Only check non-Microsoft SPs to avoid noise from first-party Microsoft services
    $thirdPartySPs = @($sps | Where-Object { $_.appOwnerOrganizationId -ne $microsoftTenantId })

    foreach ($sp in $thirdPartySPs) {
        try {
            $assignResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=100" `
                -ErrorAction Stop
            $matched = $assignResp.value | Where-Object { $sensitiveAppRoleMap.ContainsKey($_.appRoleId) }
            if ($matched) {
                $permNames = @($matched | ForEach-Object { $sensitiveAppRoleMap[$_.appRoleId] }) | Sort-Object -Unique
                $sensitiveAppPermApps.Add("$($sp.displayName) [perms: $($permNames -join ', ')]")
            }
        }
        catch {
            Write-Verbose "ENT-003: Could not check app role assignments for $($sp.displayName): $_"
        }
    }

    if ($sensitiveAppPermApps.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-003' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App: Sensitive Application Permissions (Background Access)' `
            -Status 'HIGH' `
            -Detail "Found $($sensitiveAppPermApps.Count) third-party enterprise app(s) with sensitive application-type permissions. Application permissions grant access without user context — the app operates as itself with full permission scope." `
            -Recommendation 'Review each app and confirm the application permission is strictly necessary. Remove unused permissions. Apply Conditional Access policies for workload identities where Entra ID P2 is available.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-app-consent-policies' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $sensitiveAppPermApps.ToArray()))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-003' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App: Sensitive Application Permissions' `
            -Status 'PASS' `
            -Detail 'No third-party enterprise apps with sensitive application-type permissions found.' `
            -Recommendation 'Audit application permissions when onboarding new third-party integrations.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-app-consent-policies' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ENT-004: First-party vs third-party app ratio
    # -------------------------------------------------------------------------
    $firstPartyCount = @($sps | Where-Object { $_.appOwnerOrganizationId -eq $microsoftTenantId }).Count
    $thirdPartyCount = @($sps | Where-Object { $_.appOwnerOrganizationId -ne $microsoftTenantId }).Count
    $totalSPs        = $sps.Count

    $results.Add((New-CheckResult `
        -CheckId 'ENT-004' `
        -Category 'WorkloadIdentities' `
        -Name 'Enterprise App: Third-Party Application Risk Surface' `
        -Status 'INFO' `
        -Detail "Total enabled service principals: $totalSPs. First-party (Microsoft): $firstPartyCount. Third-party: $thirdPartyCount. Third-party ratio: $([math]::Round(($thirdPartyCount / [Math]::Max($totalSPs,1)) * 100, 1))%." `
        -Recommendation 'Periodically review third-party apps. Remove those no longer used. Each third-party app is a potential supply-chain risk. Prefer pre-integrated Microsoft apps from the Entra app gallery where functionality allows.' `
        -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/what-is-application-management' `
        -CISControl '' `
        -SC300Domain 'Workload Identities' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # ENT-005: Inactive enterprise apps with admin-consented permissions
    # -------------------------------------------------------------------------
    # signInActivity is only available on beta endpoint; gracefully skip if unavailable
    try {
        $cutoff       = (Get-Date).AddDays(-30)
        $inactiveApps = [System.Collections.Generic.List[string]]::new()

        foreach ($sp in $thirdPartySPs) {
            try {
                $spDetail = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($sp.id)?`$select=id,displayName,signInActivity" `
                    -ErrorAction Stop

                $lastSignIn = $null
                if ($spDetail.signInActivity -and $spDetail.signInActivity.lastSignInDateTime) {
                    $lastSignIn = [datetime]$spDetail.signInActivity.lastSignInDateTime
                }

                # Only flag apps that have app role assignments (consented permissions) but no recent sign-in
                $hasAssignments = $false
                $assignCheck = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=1" `
                    -ErrorAction Stop
                $hasAssignments = $assignCheck.value.Count -gt 0

                if ($hasAssignments -and ($null -eq $lastSignIn -or $lastSignIn -lt $cutoff)) {
                    $signInLabel = if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd') } else { 'never' }
                    $inactiveApps.Add("$($sp.displayName) [last sign-in: $signInLabel]")
                }
            }
            catch {
                Write-Verbose "ENT-005: Could not check sign-in activity for $($sp.displayName): $_"
            }
        }

        if ($inactiveApps.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'ENT-005' `
                -Category 'WorkloadIdentities' `
                -Name 'Enterprise App: Inactive Apps With Admin-Consented Permissions' `
                -Status 'MEDIUM' `
                -Detail "Found $($inactiveApps.Count) third-party enterprise app(s) with consented permissions that have had no sign-in activity in the last 30 days. Inactive apps with standing permissions increase the tenant attack surface." `
                -Recommendation 'Review each inactive app with the application owner. Revoke consents and disable or delete apps that are no longer actively used.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/application-sign-in-unexpected-error-occurred' `
                -CISControl '' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects $inactiveApps.ToArray()))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'ENT-005' `
                -Category 'WorkloadIdentities' `
                -Name 'Enterprise App: Inactive Apps With Permissions' `
                -Status 'PASS' `
                -Detail 'All third-party enterprise apps with consented permissions showed sign-in activity within the last 30 days.' `
                -Recommendation 'Continue monitoring app sign-in activity. Extend inactivity window to 90 days for a broader sweep.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/application-sign-in-unexpected-error-occurred' `
                -CISControl '' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-005' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App: Inactive Apps With Permissions' `
            -Status 'INFO' `
            -Detail "Check skipped: signInActivity not available or insufficient permissions. Required: Application.Read.All, AuditLog.Read.All (beta endpoint). Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All and ensure the beta API is accessible.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/application-sign-in-unexpected-error-occurred' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ENT-006: SCIM provisioning configured (positive indicator)
    # -------------------------------------------------------------------------
    $provisionedApps = [System.Collections.Generic.List[string]]::new()

    foreach ($sp in $sps) {
        try {
            $syncResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/synchronization/jobs?`$top=5" `
                -ErrorAction Stop
            if ($syncResp.value.Count -gt 0) {
                $jobStates = @($syncResp.value | ForEach-Object { $_.state.code }) -join ', '
                $provisionedApps.Add("$($sp.displayName) [sync jobs: $($syncResp.value.Count), states: $jobStates]")
            }
        }
        catch {
            # 404 is expected for apps without provisioning — suppress
            if ($_ -notmatch '404') {
                Write-Verbose "ENT-006: Could not check sync jobs for $($sp.displayName): $_"
            }
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'ENT-006' `
        -Category 'WorkloadIdentities' `
        -Name 'Enterprise App: SCIM Provisioning Configured' `
        -Status 'INFO' `
        -Detail "Found $($provisionedApps.Count) enterprise app(s) with SCIM synchronization/provisioning jobs configured. SCIM provisioning is a positive practice for lifecycle management — users and groups are automatically assigned/deprovisioned." `
        -Recommendation 'Where possible, enable SCIM provisioning for enterprise apps that support it. This reduces manual access management and ensures timely deprovisioning when users leave.' `
        -Reference 'https://learn.microsoft.com/entra/identity/app-provisioning/user-provisioning' `
        -CISControl '' `
        -SC300Domain 'Workload Identities' `
        -LicenseRequired 'E3' `
        -AffectedObjects $provisionedApps.ToArray()))

    return $results
}
