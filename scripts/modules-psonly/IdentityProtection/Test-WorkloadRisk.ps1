#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Audits risky workload identities (service principals), OAuth2 grants, and app permissions. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgRiskyServicePrincipal -All, Get-MgServicePrincipal -All,
    and Get-MgOauth2PermissionGrant -All instead of raw Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    Microsoft.Graph.Identity.SignIns provides Get-MgRiskyServicePrincipal as a native
    cmdlet. Microsoft.Graph.Applications provides Get-MgServicePrincipal for app
    inventory and Get-MgOauth2PermissionGrant for OAuth2 delegated permission grants.

    SEE ALSO (Graph variant):
        scripts/modules/IdentityProtection/Test-WorkloadRisk.ps1

    Required connection:
        Connect-MgGraph -Scopes "IdentityRiskyServicePrincipal.Read.All","Application.Read.All","Directory.Read.All"

    Required scopes:
        IdentityRiskyServicePrincipal.Read.All
        Application.Read.All
        Directory.Read.All

    Required modules:
        Microsoft.Graph.Identity.SignIns
        Microsoft.Graph.Applications

    License: Entra ID P2 (E5) for risky service principal data
    SC-300 Domain: Identity Protection

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-WorkloadRisk {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # High-risk app role IDs (well-known sensitive delegated permissions)
    $highRiskRoleIds = @(
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8',  # RoleManagement.ReadWrite.Directory
        '06b708a9-e830-4db3-a914-8e69da51d44f',  # AppRoleAssignment.ReadWrite.All
        '1138cb37-bd11-4084-a2b7-9f71582aeddb',  # Device.ReadWrite.All
        '62a82d76-70ea-41e2-9197-370581804d09',  # Group.ReadWrite.All
        '741f803b-c850-494e-b5df-cde7c675a1ca',  # User.ReadWrite.All
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7',  # Directory.ReadWrite.All
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',  # Application.ReadWrite.All
        '246dd0d5-5bd0-4def-940b-0421030a5b68',  # Policy.ReadWrite.ConditionalAccess
        '0c0bf378-bf22-4481-8f81-9e89a9b4960a',  # Mail.ReadWrite (all users)
        'e2a3a72e-5f79-4c64-b1b1-878b674786c9'   # Mail.Send (all users)
    )

    $sensitiveDelegatedScopes = @(
        'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All',
        'Calendars.ReadWrite', 'Contacts.ReadWrite',
        'User.ReadWrite.All', 'Directory.ReadWrite.All',
        'RoleManagement.ReadWrite.Directory', 'Policy.ReadWrite.ConditionalAccess'
    )

    # -------------------------------------------------------------------------
    # WRI-001: Risky service principals
    # Get-MgRiskyServicePrincipal -All (Entra ID P2 required)
    # -------------------------------------------------------------------------
    try {
        $riskySpns = Get-MgRiskyServicePrincipal `
            -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" `
            -All `
            -ErrorAction Stop

        $highRiskSpns   = @($riskySpns | Where-Object { $_.RiskLevel -eq 'high' })
        $confirmedSpns  = @($riskySpns | Where-Object { $_.RiskState -eq 'confirmedCompromised' })

        if ($confirmedSpns.Count -gt 0) {
            $wri001Status = 'CRITICAL'
            $wri001Detail = "CRITICAL: $($confirmedSpns.Count) service principal(s) are in 'confirmedCompromised' state. High-risk: $($highRiskSpns.Count). Total active risky SPNs: $(($riskySpns | Measure-Object).Count)."
        }
        elseif ($highRiskSpns.Count -gt 0) {
            $wri001Status = 'HIGH'
            $wri001Detail = "$($highRiskSpns.Count) service principal(s) at high risk. Total active risky SPNs: $(($riskySpns | Measure-Object).Count)."
        }
        elseif ($riskySpns.Count -gt 0) {
            $wri001Status = 'MEDIUM'
            $wri001Detail = "$($riskySpns.Count) service principal(s) with medium risk state."
        }
        else {
            $wri001Status = 'PASS'
            $wri001Detail = 'No service principals with active risk state (atRisk or confirmedCompromised).'
        }

        $results.Add((New-CheckResult `
            -CheckId 'WRI-001' `
            -Category 'IdentityProtection' `
            -Name 'Risky Workload Identities (Service Principals)' `
            -Status $wri001Status `
            -Detail $wri001Detail `
            -Recommendation 'Investigate risky service principals in Entra ID Protection. For confirmedCompromised SPNs: rotate client secrets/certificates immediately, review recent audit log for the SPN, revoke outstanding token grants.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/concept-workload-identity-risk' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @($riskySpns | Select-Object -First 20 | ForEach-Object { $_.DisplayName })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'WRI-001' `
            -Category 'IdentityProtection' `
            -Name 'Risky Workload Identities (Service Principals)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or Entra ID P2 not licensed. Required: IdentityRiskyServicePrincipal.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "IdentityRiskyServicePrincipal.Read.All". Requires Entra ID P2 / E5.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/concept-workload-identity-risk' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # WRI-002: Service principals with high-risk app roles
    # Get-MgServicePrincipal -All with AppRoles
    # -------------------------------------------------------------------------
    try {
        $allSpns = Get-MgServicePrincipal `
            -All `
            -Property 'id,displayName,appRoles,createdDateTime,tags' `
            -ErrorAction Stop

        # Get app role assignments (what roles have been granted TO service principals)
        # Note: this uses the application role assignments endpoint
        $spnsWithHighRiskRoles = [System.Collections.Generic.List[string]]::new()

        foreach ($spn in $allSpns) {
            try {
                $roleAssignments = Get-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $spn.Id `
                    -All `
                    -ErrorAction SilentlyContinue

                if ($roleAssignments) {
                    $highRiskAssignments = @($roleAssignments | Where-Object {
                        $_.AppRoleId -in $highRiskRoleIds
                    })
                    if ($highRiskAssignments.Count -gt 0) {
                        [void]$spnsWithHighRiskRoles.Add("$($spn.DisplayName) ($($highRiskAssignments.Count) high-risk role(s))")
                    }
                }
            }
            catch {
                continue
            }
        }

        $wri002Status = if ($spnsWithHighRiskRoles.Count -gt 0) { 'HIGH' } else { 'PASS' }
        $wri002Detail = if ($spnsWithHighRiskRoles.Count -gt 0) {
            "$($spnsWithHighRiskRoles.Count) service principal(s) with high-risk application roles assigned: $($spnsWithHighRiskRoles | Select-Object -First 10 | Join-String -Separator '; ')."
        } else {
            "No service principals with high-risk application roles found among $($allSpns.Count) checked."
        }

        $results.Add((New-CheckResult `
            -CheckId 'WRI-002' `
            -Category 'IdentityProtection' `
            -Name 'Service Principals with High-Risk App Roles' `
            -Status $wri002Status `
            -Detail $wri002Detail `
            -Recommendation 'Review service principals with Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, or Application.ReadWrite.All permissions. Apply least-privilege: replace broad roles with specific permissions. Audit owner and creation date.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E3' `
            -AffectedObjects @($spnsWithHighRiskRoles | Select-Object -First 20)))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'WRI-002' `
            -Category 'IdentityProtection' `
            -Name 'Service Principals with High-Risk App Roles' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Application.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-application-permissions' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # WRI-003: OAuth2 delegated grants with sensitive scopes
    # Get-MgOauth2PermissionGrant -All
    # -------------------------------------------------------------------------
    try {
        $oauth2Grants = Get-MgOauth2PermissionGrant -All -ErrorAction Stop

        # Filter for grants with sensitive scopes
        $sensitiveGrants = @($oauth2Grants | Where-Object {
            $grantScope = $_.Scope -split ' '
            $hasHighRisk = $false
            foreach ($scope in $sensitiveDelegatedScopes) {
                if ($grantScope -contains $scope) { $hasHighRisk = $true; break }
            }
            $hasHighRisk
        })

        # Look for AllPrincipal (tenant-wide) grants
        $tenantWideGrants = @($sensitiveGrants | Where-Object { $_.ConsentType -eq 'AllPrincipals' })

        $wri003Status = if ($tenantWideGrants.Count -gt 0) { 'HIGH' }
                        elseif ($sensitiveGrants.Count -gt 5) { 'MEDIUM' }
                        elseif ($sensitiveGrants.Count -gt 0) { 'LOW' }
                        else { 'PASS' }

        $wri003Detail = "Total OAuth2 delegated grants: $(($oauth2Grants | Measure-Object).Count). Grants with sensitive scopes: $($sensitiveGrants.Count). Tenant-wide (AllPrincipals) sensitive grants: $($tenantWideGrants.Count)."

        $results.Add((New-CheckResult `
            -CheckId 'WRI-003' `
            -Category 'IdentityProtection' `
            -Name 'OAuth2 Delegated Grants — Sensitive Scopes' `
            -Status $wri003Status `
            -Detail $wri003Detail `
            -Recommendation 'Review tenant-wide OAuth2 grants with sensitive scopes in Entra ID → Enterprise applications → User consent. Revoke unnecessary grants. Restrict user consent via Admin consent settings to prevent future over-privileged OAuth apps.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E3' `
            -AffectedObjects @($tenantWideGrants | Select-Object -First 20 | ForEach-Object { "$($_.ClientId) — $($_.Scope)" })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'WRI-003' `
            -Category 'IdentityProtection' `
            -Name 'OAuth2 Delegated Grants — Sensitive Scopes' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Directory.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Directory.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # WRI-004: Service principals without owner / orphaned apps
    # Get-MgServicePrincipalOwner for app-only service principals
    # -------------------------------------------------------------------------
    try {
        # Focus on non-Microsoft service principals
        $allSpns = Get-MgServicePrincipal `
            -All `
            -Property 'id,displayName,appOwnerOrganizationId,tags,createdDateTime' `
            -ErrorAction Stop

        # Filter: exclude Microsoft first-party apps and managed identities
        $tenantId = (Get-MgContext).TenantId
        $thirdPartySpns = @($allSpns | Where-Object {
            $_.AppOwnerOrganizationId -ne '72f988bf-86f1-41af-91ab-2d7cd011db47' -and   # Microsoft tenant
            $_.AppOwnerOrganizationId -ne $tenantId -and
            $null -ne $_.AppOwnerOrganizationId -and
            $_.Tags -notcontains 'WindowsAzureActiveDirectoryIntegratedApp'
        })

        $orphanedSpns = [System.Collections.Generic.List[string]]::new()
        $checkedCount = 0
        foreach ($spn in ($thirdPartySpns | Select-Object -First 50)) {
            $checkedCount++
            try {
                $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $spn.Id -All -ErrorAction SilentlyContinue
                if ($null -eq $owners -or ($owners | Measure-Object).Count -eq 0) {
                    [void]$orphanedSpns.Add($spn.DisplayName)
                }
            }
            catch {
                continue
            }
        }

        $wri004Status = if ($orphanedSpns.Count -gt 10) { 'MEDIUM' }
                        elseif ($orphanedSpns.Count -gt 0) { 'LOW' }
                        else { 'PASS' }

        $wri004Detail = "Third-party service principals checked (first 50 of $($thirdPartySpns.Count)): $checkedCount. Orphaned (no owner assigned): $($orphanedSpns.Count)."

        $results.Add((New-CheckResult `
            -CheckId 'WRI-004' `
            -Category 'IdentityProtection' `
            -Name 'Orphaned Service Principals (No Owner)' `
            -Status $wri004Status `
            -Detail $wri004Detail `
            -Recommendation 'Assign owners to all non-Microsoft service principals. Owners are responsible for managing credentials, permissions, and lifecycle. Orphaned apps with no owner are often stale and should be reviewed for removal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/overview-assign-app-owners' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E3' `
            -AffectedObjects @($orphanedSpns | Select-Object -First 20)))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'WRI-004' `
            -Category 'IdentityProtection' `
            -Name 'Orphaned Service Principals (No Owner)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Application.Read.All + Directory.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/overview-assign-app-owners' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
