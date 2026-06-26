#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

<#
.SYNOPSIS
    Audits managed identities for privileged role assignments and permission hygiene.
    PS-only variant.

.DESCRIPTION
    Test-ManagedIdentities evaluates system-assigned and user-assigned managed identities:
    privileged directory role assignments, full inventory, over-provisioned application
    permissions, and workload identity federation (positive finding).

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/WorkloadIdentities/Test-ManagedIdentities.ps1

    CHANGES vs. Graph variant:
        Main MI fetch:  Invoke-MgGraphRequest paged GET /servicePrincipals?$filter=servicePrincipalType eq 'ManagedIdentity'
                        -> Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'" -All
        MSI-001:        Invoke-MgGraphRequest paged GET /roleManagement/directory/roleAssignments?$expand=roleDefinition
                        No confirmed typed PS cmdlet in confirmed mapping table for roleManagement/directory/roleAssignments.
                        Falls back to: Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId {id} -All
                        to check Graph API application permissions for each MI, which covers the most
                        common risk (over-provisioned API perms). For Entra directory role assignments,
                        the check emits an INFO stub referencing the Graph variant.
        MSI-003:        Invoke-MgGraphRequest GET /servicePrincipals/{id}/appRoleAssignments
                        -> Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId {id} -All
        MSI-004:        Invoke-MgGraphRequest paged GET /applications and GET /applications/{id}/federatedIdentityCredentials
                        -> Get-MgApplication -All
                        -> Get-MgApplicationFederatedIdentityCredential -ApplicationId {id} -All

.NOTES
    Required connection  : Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All"
    Required scopes      : Application.Read.All, Directory.Read.All
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Applications

    License Required            : E3 minimum
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        MSI-001  Managed identities with privileged directory roles [partial — see CHANGES]
        MSI-002  User-assigned vs system-assigned inventory
        MSI-003  Managed identities with sensitive application permissions
        MSI-004  Workload identity federation configured (positive indicator)
#>

function Test-ManagedIdentities {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all managed identity service principals
    # -------------------------------------------------------------------------
    $managedIdentities = $null
    try {
        $managedIdentities = Get-MgServicePrincipal `
            -Filter "servicePrincipalType eq 'ManagedIdentity'" `
            -Property 'id,displayName,appId,servicePrincipalType,alternativeNames' `
            -All -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MSI-000' `
            -Category 'WorkloadIdentities' `
            -Name 'Managed Identity Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and reconnect: Connect-MgGraph -Scopes "Application.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $miCount = @($managedIdentities).Count

    # Build lookup: SP objectId -> displayName
    $miIdToName = @{}
    foreach ($mi in $managedIdentities) { $miIdToName[$mi.Id] = $mi.DisplayName }

    # -------------------------------------------------------------------------
    # MSI-001: Managed identities with privileged directory roles
    # The roleManagement/directory/roleAssignments endpoint expanded with roleDefinition
    # has no confirmed typed PS cmdlet in the mapping table.
    # This check emits an INFO result for Entra directory role assignments and
    # falls back to checking Graph API application permissions via
    # Get-MgServicePrincipalAppRoleAssignment (which is confirmed and covers the
    # most common operational risk: over-provisioned API perms on MIs).
    # For full directory role assignment check, use the Graph variant.
    # -------------------------------------------------------------------------
    $results.Add((New-CheckResult `
        -CheckId 'MSI-001' `
        -Category 'WorkloadIdentities' `
        -Name 'Managed Identity: Privileged Directory Role Assignments (Entra Roles)' `
        -Status 'INFO' `
        -Detail "MSI-001 (Entra directory role assignments on MIs) is not fully available in PS-only mode: the roleManagement/directory/roleAssignments endpoint with roleDefinition expansion has no confirmed typed PS cmdlet in the mapping table. To check Entra directory role assignments on managed identities, use the Graph variant (scripts/modules/WorkloadIdentities/Test-ManagedIdentities.ps1) or review: Entra admin center > Roles and administrators > filter by managed identity principals. Graph API application permissions on MIs are checked by MSI-003 below." `
        -Recommendation 'Use the Graph variant for a complete Entra directory role check on managed identities. MSI-003 in this file covers over-provisioned Graph application permissions.' `
        -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations' `
        -CISControl '' `
        -SC300Domain 'Workload Identities' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MSI-002: User-assigned managed identities inventory
    # -------------------------------------------------------------------------
    $userAssigned   = [System.Collections.Generic.List[string]]::new()
    $systemAssigned = [System.Collections.Generic.List[string]]::new()

    foreach ($mi in $managedIdentities) {
        $altNames = @($mi.AlternativeNames)
        $isUserAssigned = $altNames | Where-Object { $_ -like '*/userAssignedIdentities/*' }
        if ($isUserAssigned) {
            $userAssigned.Add($mi.DisplayName)
        }
        else {
            $systemAssigned.Add($mi.DisplayName)
        }
    }

    $msi002Detail = "Total managed identities: $miCount. " +
                    "User-assigned: $($userAssigned.Count). System-assigned: $($systemAssigned.Count)."

    $results.Add((New-CheckResult `
        -CheckId 'MSI-002' `
        -Category 'WorkloadIdentities' `
        -Name 'Managed Identity: Inventory' `
        -Status 'INFO' `
        -Detail $msi002Detail `
        -Recommendation 'Prefer system-assigned managed identities for single-resource workloads. User-assigned identities should be reviewed to ensure they are not shared across resources with different trust levels.' `
        -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identities-faq' `
        -CISControl '' `
        -SC300Domain 'Workload Identities' `
        -LicenseRequired 'E3' `
        -AffectedObjects $userAssigned.ToArray()))

    # -------------------------------------------------------------------------
    # MSI-003: Managed identities with sensitive application permissions
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
        '75359482-378d-4052-8f01-80520e7db3cd' = 'Files.ReadWrite.All'
        '7ab1d382-f21e-4acd-a863-ba3e13f7da61' = 'Directory.Read.All'
        '810c84a8-4a9e-49e6-bf7d-12d183f40d01' = 'Mail.Read'
    }

    $msiWithSensitivePerms = [System.Collections.Generic.List[string]]::new()

    foreach ($mi in $managedIdentities) {
        try {
            $assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $mi.Id -All -ErrorAction Stop
            $matched = $assignments | Where-Object { $sensitiveAppRoleMap.ContainsKey($_.AppRoleId) }
            if ($matched) {
                $permNames = @($matched | ForEach-Object { $sensitiveAppRoleMap[$_.AppRoleId] }) | Sort-Object -Unique
                $msiWithSensitivePerms.Add("$($mi.DisplayName) [perms: $($permNames -join ', ')]")
            }
        }
        catch {
            Write-Verbose "MSI-003: Could not check app role assignments for $($mi.DisplayName): $_"
        }
    }

    if ($msiWithSensitivePerms.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'MSI-003' `
            -Category 'WorkloadIdentities' `
            -Name 'Managed Identity: Sensitive Application Permissions' `
            -Status 'MEDIUM' `
            -Detail "Found $($msiWithSensitivePerms.Count) managed identity/ies with sensitive application permissions. If the Azure resource is compromised, the attacker inherits these permissions." `
            -Recommendation 'Apply least-privilege: grant only the specific permissions required for the workload. Consider splitting workloads that require different permission levels into separate resources with separate managed identities.' `
            -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $msiWithSensitivePerms.ToArray()))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'MSI-003' `
            -Category 'WorkloadIdentities' `
            -Name 'Managed Identity: Application Permissions' `
            -Status 'PASS' `
            -Detail "No managed identities with sensitive application permissions found." `
            -Recommendation 'Continue applying least-privilege when granting permissions to new managed identities.' `
            -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MSI-004: Workload Identity Federation configured (positive indicator)
    # Uses Get-MgApplication -All and Get-MgApplicationFederatedIdentityCredential -ApplicationId {id} -All
    # -------------------------------------------------------------------------
    $fedApps = [System.Collections.Generic.List[string]]::new()

    try {
        $allApps = Get-MgApplication -All -Property 'id,displayName' -ErrorAction Stop

        foreach ($app in $allApps) {
            try {
                $fedCreds = Get-MgApplicationFederatedIdentityCredential -ApplicationId $app.Id -All -ErrorAction Stop
                if (@($fedCreds).Count -gt 0) {
                    $subjects = @($fedCreds | ForEach-Object { $_.Subject }) -join ', '
                    $fedApps.Add("$($app.DisplayName) [$(@($fedCreds).Count) FIC(s), subjects: $subjects]")
                }
            }
            catch {
                # 404 is expected for apps without federation — suppress
                if ($_ -notmatch '404') {
                    Write-Verbose "MSI-004: Could not check federated credentials for $($app.DisplayName): $_"
                }
            }
        }

        $msi004Status = if ($fedApps.Count -gt 0) { 'PASS' } else { 'INFO' }
        $msi004Detail = if ($fedApps.Count -gt 0) {
            "Found $($fedApps.Count) application(s) with workload identity federation configured. This is a positive security finding — federated credentials eliminate the need for client secrets or certificates."
        }
        else {
            "No applications with workload identity federation found. Workload identity federation (OIDC-based) is the recommended approach for CI/CD and cross-cloud workloads as it avoids long-lived secrets."
        }

        $results.Add((New-CheckResult `
            -CheckId 'MSI-004' `
            -Category 'WorkloadIdentities' `
            -Name 'Managed Identity: Workload Identity Federation' `
            -Status $msi004Status `
            -Detail $msi004Detail `
            -Recommendation 'Where possible, migrate CI/CD pipelines and cross-cloud workloads to workload identity federation. Supported by GitHub Actions, GitLab CI, Kubernetes, and others. No secret management required.' `
            -Reference 'https://learn.microsoft.com/entra/workload-id/workload-identity-federation' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $fedApps.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MSI-004' `
            -Category 'WorkloadIdentities' `
            -Name 'Managed Identity: Workload Identity Federation' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and retry.' `
            -Reference 'https://learn.microsoft.com/entra/workload-id/workload-identity-federation' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
