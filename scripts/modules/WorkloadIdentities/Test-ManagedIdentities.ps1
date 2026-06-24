#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits managed identities for privileged role assignments and permission hygiene.

.DESCRIPTION
    Test-ManagedIdentities evaluates system-assigned and user-assigned managed identities:
    privileged directory role assignments, full inventory, over-provisioned application
    permissions, and workload identity federation (positive finding).

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

.NOTES
    Required Graph Permissions : Application.Read.All, RoleManagement.Read.All
    License Required            : E3 minimum
    Module                      : Microsoft.Graph.Authentication (uses Invoke-MgGraphRequest)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        MSI-001  Managed identities with privileged directory roles
        MSI-002  User-assigned managed identities inventory
        MSI-003  Managed identities with application permissions
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
    $managedIdentities = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $miUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=servicePrincipalType eq 'ManagedIdentity'&`$select=id,displayName,appId,servicePrincipalType,alternativeNames&`$top=999"
        do {
            $miResponse = Invoke-MgGraphRequest -Method GET -Uri $miUri -ErrorAction Stop
            foreach ($mi in $miResponse.value) { $managedIdentities.Add($mi) }
            $miUri = $miResponse.'@odata.nextLink'
        } while ($miUri)
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MSI-000' `
            -Category 'WorkloadIdentities' `
            -Name 'Managed Identity Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $miIds = @($managedIdentities | ForEach-Object { $_.id })

    # Build a lookup: SP objectId -> displayName
    $miIdToName = @{}
    foreach ($mi in $managedIdentities) { $miIdToName[$mi.id] = $mi.displayName }

    # -------------------------------------------------------------------------
    # MSI-001: Managed identities with privileged directory roles
    # -------------------------------------------------------------------------
    # Privileged role display names to flag
    $privilegedRoleNames = @(
        'Global Administrator',
        'Privileged Role Administrator',
        'Application Administrator',
        'Cloud Application Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'User Account Administrator',
        'Hybrid Identity Administrator',
        'Security Administrator',
        'Intune Administrator',
        'Privileged Authentication Administrator'
    )

    try {
        # Retrieve all active role assignments
        $roleUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition&$top=999'
        $allAssignments = [System.Collections.Generic.List[hashtable]]::new()
        do {
            $raPage = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction Stop
            foreach ($ra in $raPage.value) { $allAssignments.Add($ra) }
            $roleUri = $raPage.'@odata.nextLink'
        } while ($roleUri)

        $privilegedMSIs = [System.Collections.Generic.List[string]]::new()

        foreach ($assignment in $allAssignments) {
            $principalId = $assignment.principalId
            if ($principalId -notin $miIds) { continue }

            $roleName = $assignment.roleDefinition.displayName
            if ($roleName -in $privilegedRoleNames) {
                $miName = if ($miIdToName.ContainsKey($principalId)) { $miIdToName[$principalId] } else { $principalId }
                $privilegedMSIs.Add("$miName [role: $roleName]")
            }
        }

        if ($privilegedMSIs.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'MSI-001' `
                -Category 'WorkloadIdentities' `
                -Name 'Managed Identity: Privileged Directory Role Assignments' `
                -Status 'HIGH' `
                -Detail "Found $($privilegedMSIs.Count) managed identity/ies with privileged Entra ID directory roles. Managed identities with Global Admin or equivalent roles pose a critical privilege escalation risk if the associated Azure resource is compromised." `
                -Recommendation 'Remove privileged directory roles from managed identities. Use least-privilege Graph API application permissions instead of directory roles. If roles are required, restrict the hosting resource with Azure Policy and JIT access.' `
                -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations' `
                -CISControl '' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects $privilegedMSIs.ToArray()))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'MSI-001' `
                -Category 'WorkloadIdentities' `
                -Name 'Managed Identity: Privileged Role Assignments' `
                -Status 'PASS' `
                -Detail "No managed identities with privileged directory roles found. Checked $($managedIdentities.Count) managed identities against $($allAssignments.Count) role assignments." `
                -Recommendation 'Continue monitoring role assignments. Prohibit assigning admin roles to managed identities through Azure Policy.' `
                -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations' `
                -CISControl '' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MSI-001' `
            -Category 'WorkloadIdentities' `
            -Name 'Managed Identity: Privileged Role Assignments' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MSI-002: User-assigned managed identities inventory
    # -------------------------------------------------------------------------
    # Distinguish user-assigned from system-assigned via alternativeNames
    # User-assigned MIs have alternativeNames containing the resource URI with 'userAssignedIdentities'
    $userAssigned   = [System.Collections.Generic.List[string]]::new()
    $systemAssigned = [System.Collections.Generic.List[string]]::new()

    foreach ($mi in $managedIdentities) {
        $altNames = @($mi.alternativeNames)
        $isUserAssigned = $altNames | Where-Object { $_ -like '*/userAssignedIdentities/*' }
        if ($isUserAssigned) {
            $userAssigned.Add($mi.displayName)
        }
        else {
            $systemAssigned.Add($mi.displayName)
        }
    }

    $msi002Detail = "Total managed identities: $($managedIdentities.Count). " +
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
    # MSI-003: Managed identities with application permissions
    # -------------------------------------------------------------------------
    # Sensitive application permission GUIDs
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
            $assignResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($mi.id)/appRoleAssignments?`$top=100" `
                -ErrorAction Stop

            $matched = $assignResp.value | Where-Object { $sensitiveAppRoleMap.ContainsKey($_.appRoleId) }
            if ($matched) {
                $permNames = @($matched | ForEach-Object { $sensitiveAppRoleMap[$_.appRoleId] }) | Sort-Object -Unique
                $msiWithSensitivePerms.Add("$($mi.displayName) [perms: $($permNames -join ', ')]")
            }
        }
        catch {
            Write-Verbose "MSI-003: Could not check app role assignments for $($mi.displayName): $_"
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
    # -------------------------------------------------------------------------
    # Federated identity credentials are on application objects, not service principals
    # Retrieve application registrations and check for federatedIdentityCredentials
    $fedApps = [System.Collections.Generic.List[string]]::new()

    try {
        $appUri = 'https://graph.microsoft.com/v1.0/applications?$select=id,displayName&$top=999'
        $appIds = [System.Collections.Generic.List[hashtable]]::new()
        do {
            $appPage = Invoke-MgGraphRequest -Method GET -Uri $appUri -ErrorAction Stop
            foreach ($a in $appPage.value) { $appIds.Add($a) }
            $appUri = $appPage.'@odata.nextLink'
        } while ($appUri)

        foreach ($app in $appIds) {
            try {
                $fedCredsResp = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)/federatedIdentityCredentials?`$top=10" `
                    -ErrorAction Stop

                if ($fedCredsResp.value.Count -gt 0) {
                    $subjects = @($fedCredsResp.value | ForEach-Object { $_.subject }) -join ', '
                    $fedApps.Add("$($app.displayName) [$($fedCredsResp.value.Count) FIC(s), subjects: $subjects]")
                }
            }
            catch {
                # 404 is expected for apps without federation
                if ($_ -notmatch '404') {
                    Write-Verbose "MSI-004: Could not check federated credentials for $($app.displayName): $_"
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
