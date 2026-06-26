#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Audits enterprise applications (service principals) for access control and permission risks.
    PS-only variant.

.DESCRIPTION
    Test-EnterpriseApps evaluates the tenant's enterprise app (service principal) estate:
    user assignment requirement, tenant-wide admin-consented permissions, application-type
    permissions on sensitive resources, third-party app ratio, inactive apps with consented
    access, and SCIM provisioning coverage.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/WorkloadIdentities/Test-EnterpriseApps.ps1

    CHANGES vs. Graph variant:
        Main SP fetch:  Invoke-MgGraphRequest paged GET /servicePrincipals?$filter=accountEnabled eq true
                        -> Get-MgServicePrincipal -Filter "accountEnabled eq true" -All
        ENT-001/003:    Invoke-MgGraphRequest GET /servicePrincipals/{id}/appRoleAssignments
                        -> Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId {id} -All
        ENT-002:        Invoke-MgGraphRequest paged GET /oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'
                        -> Get-MgOauth2PermissionGrant -Filter "consentType eq 'AllPrincipals'" -All
        ENT-005:        signInActivity on servicePrincipals is only on the beta endpoint.
                        No confirmed typed PS cmdlet in mapping table for beta SP signInActivity.
                        Falls back to INFO result with reference to Graph variant.
        ENT-006:        synchronization/jobs sub-resource has no typed PS cmdlet in confirmed list.
                        Falls back to INFO result with reference to portal.

.NOTES
    Required connection  : Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All"
    Required scopes      : Application.Read.All, Directory.Read.All
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Applications

    License Required            : E3 minimum; sign-in activity data requires E3+
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        ENT-001  Enterprise apps with user assignment NOT required
        ENT-002  Tenant-wide admin-consented delegated permissions (AllPrincipals)
        ENT-003  Enterprise apps with sensitive application permissions
        ENT-004  Third-party vs first-party app ratio (risk surface indicator)
        ENT-005  Inactive enterprise apps with admin-consented permissions [INFO stub - beta only]
        ENT-006  SCIM provisioning configured (positive indicator) [INFO stub - no typed cmdlet]
#>

function Test-EnterpriseApps {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'

    # -------------------------------------------------------------------------
    # Retrieve service principals (enterprise apps), enabled only
    # -------------------------------------------------------------------------
    $sps = $null
    try {
        $sps = Get-MgServicePrincipal -Filter "accountEnabled eq true" `
            -Property 'id,displayName,appId,appOwnerOrganizationId,appRoleAssignmentRequired,servicePrincipalType,signInAudience' `
            -All -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ENT-000' `
            -Category 'WorkloadIdentities' `
            -Name 'Enterprise App Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and reconnect: Connect-MgGraph -Scopes "Application.Read.All".' `
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
    $sensitiveAppRoles = @(
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7',
        'e2a3a72e-5f79-4c64-b1b1-878b674786c9',
        'b633e1c5-b582-4048-a93e-9f11b44c7e96',
        '741f803b-c850-494e-b5df-cde7c675a1ca',
        '5b567255-7703-4780-807c-7be8301ae99b',
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'
    )

    $noAssignmentApps = [System.Collections.Generic.List[string]]::new()

    foreach ($sp in $sps) {
        if ($sp.AppRoleAssignmentRequired -eq $true) { continue }
        if ($sp.AppOwnerOrganizationId -eq $microsoftTenantId) { continue }

        try {
            $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop
            $hasSensitive = $roleAssignments | Where-Object { $_.AppRoleId -in $sensitiveAppRoles }
            if ($hasSensitive) {
                $noAssignmentApps.Add($sp.DisplayName)
            }
        }
        catch {
            Write-Verbose "ENT-001: Could not check app role assignments for $($sp.DisplayName): $_"
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
    # Uses Get-MgOauth2PermissionGrant -Filter "consentType eq 'AllPrincipals'" -All
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
        $allGrants = Get-MgOauth2PermissionGrant -Filter "consentType eq 'AllPrincipals'" -All -ErrorAction Stop

        # Build SP display name lookup from already-retrieved $sps
        $spIdToName = @{}
        foreach ($sp in $sps) { $spIdToName[$sp.Id] = $sp.DisplayName }

        $sensitiveGrants = [System.Collections.Generic.List[string]]::new()
        foreach ($grant in $allGrants) {
            $scopes  = $grant.Scope -split ' '
            $matched = $scopes | Where-Object { $_ -in $sensitiveDelegatedScopes }
            if ($matched) {
                $spName = if ($spIdToName.ContainsKey($grant.ClientId)) { $spIdToName[$grant.ClientId] } else { $grant.ClientId }
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
                -Detail "No tenant-wide (AllPrincipals) consents found for sensitive scopes. Total AllPrincipals grants in tenant: $(@($allGrants).Count)." `
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
            -Recommendation 'Grant Application.Read.All and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ENT-003: Enterprise apps with sensitive application permissions (background)
    # Uses Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId {id} -All
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
    $thirdPartySPs = @($sps | Where-Object { $_.AppOwnerOrganizationId -ne $microsoftTenantId })

    foreach ($sp in $thirdPartySPs) {
        try {
            $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All -ErrorAction Stop
            $matched = $assignments | Where-Object { $sensitiveAppRoleMap.ContainsKey($_.AppRoleId) }
            if ($matched) {
                $permNames = @($matched | ForEach-Object { $sensitiveAppRoleMap[$_.AppRoleId] }) | Sort-Object -Unique
                $sensitiveAppPermApps.Add("$($sp.DisplayName) [perms: $($permNames -join ', ')]")
            }
        }
        catch {
            Write-Verbose "ENT-003: Could not check app role assignments for $($sp.DisplayName): $_"
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
    $firstPartyCount = @($sps | Where-Object { $_.AppOwnerOrganizationId -eq $microsoftTenantId }).Count
    $thirdPartyCount = @($sps | Where-Object { $_.AppOwnerOrganizationId -ne $microsoftTenantId }).Count
    $totalSPs        = @($sps).Count

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
    # signInActivity on servicePrincipals is only on the beta endpoint.
    # No confirmed typed PS cmdlet for beta SP signInActivity in the mapping table.
    # Emitting INFO result directing to Graph variant.
    # -------------------------------------------------------------------------
    $results.Add((New-CheckResult `
        -CheckId 'ENT-005' `
        -Category 'WorkloadIdentities' `
        -Name 'Enterprise App: Inactive Apps With Permissions' `
        -Status 'INFO' `
        -Detail "ENT-005 is not available in PS-only mode: signInActivity on service principals is only exposed on the beta endpoint and has no confirmed typed PS cmdlet in the mapping table. To check inactive enterprise apps, use the Graph variant (scripts/modules/WorkloadIdentities/Test-EnterpriseApps.ps1) or review the Entra admin center > Enterprise applications > Sign-in activity." `
        -Recommendation 'Review app sign-in activity in Entra admin center. Revoke consents and disable apps that have had no sign-in activity in 30+ days.' `
        -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/application-sign-in-unexpected-error-occurred' `
        -CISControl '' `
        -SC300Domain 'Workload Identities' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # ENT-006: SCIM provisioning configured (positive indicator)
    # synchronization/jobs sub-resource has no typed PS cmdlet in confirmed mapping table.
    # Emitting INFO result directing to portal.
    # -------------------------------------------------------------------------
    $results.Add((New-CheckResult `
        -CheckId 'ENT-006' `
        -Category 'WorkloadIdentities' `
        -Name 'Enterprise App: SCIM Provisioning Configured' `
        -Status 'INFO' `
        -Detail "ENT-006 is not available in PS-only mode: the synchronization/jobs sub-resource on service principals has no confirmed typed PS cmdlet in the mapping table. To review SCIM provisioning status, use the Graph variant (scripts/modules/WorkloadIdentities/Test-EnterpriseApps.ps1) or inspect Entra admin center > Enterprise applications > Provisioning." `
        -Recommendation 'Where possible, enable SCIM provisioning for enterprise apps that support it. This reduces manual access management and ensures timely deprovisioning when users leave.' `
        -Reference 'https://learn.microsoft.com/entra/identity/app-provisioning/user-provisioning' `
        -CISControl '' `
        -SC300Domain 'Workload Identities' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
