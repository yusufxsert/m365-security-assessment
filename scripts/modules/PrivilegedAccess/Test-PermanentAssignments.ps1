#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests for permanent (non-PIM) privileged role assignments in Azure AD.

.DESCRIPTION
    Identifies permanently active role assignments for high-privilege roles
    including Global Administrator, Privileged Role Administrator, and other
    Tier-0 roles. Also detects service principals, groups, and administrative
    unit scoping anomalies.

.NOTES
    Required Permissions:
        - RoleManagement.Read.All
        - User.Read.All

    License: Microsoft 365 E3 / E5 (role assignment read does not require P2)
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
#>

function Test-PermanentAssignments {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Well-known role definition IDs
    $roleDefIds = @{
        'Global Administrator'           = '62e90394-69f5-4237-9190-012177145e10'
        'Privileged Role Administrator'  = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
        'User Account Administrator'     = 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        'Security Administrator'         = '194ae4cb-b126-40b2-bd5b-6091b380977d'
        'Exchange Administrator'         = '29232cdf-9323-42fd-ade2-1d097af3e4de'
        'SharePoint Administrator'       = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
        'Compliance Administrator'       = '17315797-102d-40b4-93e0-432062caca18'
    }

    # Helper to get permanent role members (assignmentType = Assigned, no expiration)
    function Get-PermanentRoleMembers {
        param([string]$RoleDefinitionId, [string]$RoleName)

        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$filter=roleDefinitionId eq '$RoleDefinitionId'&`$expand=principal&`$top=999"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $assignments = $response.value | Where-Object {
            $_.assignmentType -eq 'Assigned' -and
            $_.scheduleInfo.expiration.type -eq 'noExpiration'
        }
        return $assignments
    }

    # -------------------------------------------------------------------------
    # PRM-001: Permanent Global Administrator assignments
    # -------------------------------------------------------------------------
    try {
        $gaRoleDefId = $roleDefIds['Global Administrator']
        $permanentGAs = Get-PermanentRoleMembers -RoleDefinitionId $gaRoleDefId -RoleName 'Global Administrator'
        $count = ($permanentGAs | Measure-Object).Count

        $affectedObjects = $permanentGAs | ForEach-Object {
            $p = $_.principal
            if ($p) { "$($p.displayName) ($($p.userPrincipalName ?? $p.id))" }
        } | Where-Object { $_ }

        if ($count -gt 2) {
            $status = 'CRITICAL'
            $detail = "$count permanent Global Administrator assignments found (threshold: >2). These should be converted to PIM Eligible assignments."
        }
        elseif ($count -gt 0) {
            $status = 'HIGH'
            $detail = "$count permanent Global Administrator assignment(s) found. Even break-glass accounts should ideally use PIM. Verify these are intentional emergency accounts."
        }
        else {
            $status = 'PASS'
            $detail = 'No permanent Global Administrator assignments found. All GA access appears to use PIM.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'PRM-001' `
            -Category 'PrivilegedAccess' `
            -Name 'Permanent Global Administrator assignments' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Convert all Global Administrator assignments to PIM Eligible. Only break-glass accounts (max 2) should remain as permanently active, and those should be cloud-only accounts with no day-to-day use.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl 'CIS M365 1.1.2' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $affectedObjects))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PRM-001' `
            -Category 'PrivilegedAccess' `
            -Name 'Permanent Global Administrator assignments' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl 'CIS M365 1.1.2' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PRM-002: Permanent Privileged Role Administrator assignments
    # -------------------------------------------------------------------------
    try {
        $praRoleDefId = $roleDefIds['Privileged Role Administrator']
        $permanentPRAs = Get-PermanentRoleMembers -RoleDefinitionId $praRoleDefId -RoleName 'Privileged Role Administrator'
        $count = ($permanentPRAs | Measure-Object).Count

        $affectedObjects = $permanentPRAs | ForEach-Object {
            $p = $_.principal
            if ($p) { "$($p.displayName) ($($p.userPrincipalName ?? $p.id))" }
        } | Where-Object { $_ }

        if ($count -gt 0) {
            $status = 'HIGH'
            $detail = "$count permanent Privileged Role Administrator assignment(s) found. This role can modify all role assignments and should be strictly JIT via PIM."
        }
        else {
            $status = 'PASS'
            $detail = 'No permanent Privileged Role Administrator assignments found.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'PRM-002' `
            -Category 'PrivilegedAccess' `
            -Name 'Permanent Privileged Role Administrator assignments' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Convert all Privileged Role Administrator assignments to PIM Eligible with short activation duration (max 4h), MFA, and justification required.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-getting-started' `
            -CISControl 'CIS M365 1.1.3' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $affectedObjects))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PRM-002' `
            -Category 'PrivilegedAccess' `
            -Name 'Permanent Privileged Role Administrator assignments' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-getting-started' `
            -CISControl 'CIS M365 1.1.3' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PRM-003: Permanent assignments for Tier-0 roles
    # -------------------------------------------------------------------------
    $tier0Roles = @(
        'User Account Administrator',
        'Security Administrator',
        'Exchange Administrator',
        'SharePoint Administrator',
        'Compliance Administrator'
    )

    foreach ($roleName in $tier0Roles) {
        $roleDefId = $roleDefIds[$roleName]
        try {
            $permanentMembers = Get-PermanentRoleMembers -RoleDefinitionId $roleDefId -RoleName $roleName
            $count = ($permanentMembers | Measure-Object).Count

            $affectedObjects = $permanentMembers | ForEach-Object {
                $p = $_.principal
                if ($p) { "$($p.displayName) ($($p.userPrincipalName ?? $p.id))" }
            } | Where-Object { $_ }

            if ($count -gt 0) {
                $status = 'HIGH'
                $detail = "$count permanent '$roleName' assignment(s) found."
            }
            else {
                $status = 'PASS'
                $detail = "No permanent '$roleName' assignments found."
            }

            # Derive a stable CheckId suffix from role name
            $roleShort = ($roleName -replace '[^A-Za-z]', '').Substring(0, [math]::Min(6, ($roleName -replace '[^A-Za-z]','').Length))
            $results.Add((New-CheckResult `
                -CheckId "PRM-003-$roleShort" `
                -Category 'PrivilegedAccess' `
                -Name "Permanent $roleName assignments" `
                -Status $status `
                -Detail $detail `
                -Recommendation "Convert all '$roleName' assignments to PIM Eligible. Permanent assignments to this role increase standing attack surface." `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
                -CISControl '' `
                -SC300Domain 'Identity Governance' `
                -LicenseRequired 'E5' `
                -AffectedObjects $affectedObjects))
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId "PRM-003-$roleName" `
                -Category 'PrivilegedAccess' `
                -Name "Permanent $roleName assignments" `
                -Status 'INFO' `
                -Detail "Check skipped: insufficient permissions or role not found. Required: RoleManagement.Read.All. Error: $_" `
                -Recommendation 'Grant RoleManagement.Read.All permission.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
                -CISControl '' `
                -SC300Domain 'Identity Governance' `
                -LicenseRequired 'E5' `
                -AffectedObjects @()))
        }
    }

    # -------------------------------------------------------------------------
    # PRM-004: Service accounts with privileged role assignments
    # -------------------------------------------------------------------------
    try {
        # Get all active role assignment schedules (all roles)
        $allAssignUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$expand=principal&$top=999'
        $allAssignResponse = Invoke-MgGraphRequest -Method GET -Uri $allAssignUri -ErrorAction Stop
        $allAssignments = $allAssignResponse.value | Where-Object {
            $_.assignmentType -eq 'Assigned' -and
            $_.scheduleInfo.expiration.type -eq 'noExpiration'
        }

        # Identify service principals (non-interactive / app identities)
        $spAssignments = $allAssignments | Where-Object {
            $_.principal.'@odata.type' -eq '#microsoft.graph.servicePrincipal'
        }

        # Also flag user accounts with service-account-like names
        $svcNamePattern = '(?i)(svc|service|svc\.|app|bot|automation|noreply|system|daemon)'
        $svcUserAssignments = $allAssignments | Where-Object {
            $_.principal.'@odata.type' -eq '#microsoft.graph.user' -and
            $_.principal.displayName -match $svcNamePattern
        }

        $allSvcAssignments = @($spAssignments) + @($svcUserAssignments)
        $count = ($allSvcAssignments | Measure-Object).Count

        $affectedObjects = $allSvcAssignments | ForEach-Object {
            $p = $_.principal
            $roleId = $_.roleDefinitionId
            if ($p) { "$($p.displayName) [$($p.'@odata.type' -replace '#microsoft.graph.', '')] → roleDefId: $roleId" }
        } | Where-Object { $_ }

        if ($count -gt 0) {
            $status = 'HIGH'
            $detail = "$count service account(s) / service principal(s) found with permanent privileged role assignments. Service identities should use app-level permissions, not directory roles."
        }
        else {
            $status = 'PASS'
            $detail = 'No service accounts or service principals found with permanent privileged role assignments.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'PRM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'Service accounts with privileged role assignments' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Remove privileged directory roles from service accounts and service principals. Use Graph API application permissions with least privilege instead of directory roles.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl 'CIS M365 1.3.8' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $affectedObjects))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PRM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'Service accounts with privileged role assignments' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl 'CIS M365 1.3.8' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PRM-005: Privileged role assignments to groups
    # -------------------------------------------------------------------------
    try {
        $allAssignUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal&$top=999'
        $allAssignResponse = Invoke-MgGraphRequest -Method GET -Uri $allAssignUri -ErrorAction Stop
        $allAssignments = $allAssignResponse.value

        $groupAssignments = $allAssignments | Where-Object {
            $_.principal.'@odata.type' -eq '#microsoft.graph.group'
        }

        $count = ($groupAssignments | Measure-Object).Count

        $affectedObjects = $groupAssignments | ForEach-Object {
            $p = $_.principal
            $roleId = $_.roleDefinitionId
            if ($p) { "$($p.displayName) (Group) → roleDefId: $roleId" }
        } | Where-Object { $_ }

        if ($count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$count group(s) assigned to privileged directory roles. Group membership may not be visible to all admins, reducing auditability."
        }
        else {
            $status = 'PASS'
            $detail = 'No groups found with privileged directory role assignments.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'PRM-005' `
            -Category 'PrivilegedAccess' `
            -Name 'Privileged role assignments to groups' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Avoid assigning privileged roles to groups unless using role-assignable groups with tight membership controls and access reviews. Prefer direct user assignments via PIM for full auditability.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $affectedObjects))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PRM-005' `
            -Category 'PrivilegedAccess' `
            -Name 'Privileged role assignments to groups' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/groups-concept' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PRM-006: Role assignment scope (directory vs administrative unit) – INFO
    # -------------------------------------------------------------------------
    try {
        $allAssignUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$top=999'
        $allAssignResponse = Invoke-MgGraphRequest -Method GET -Uri $allAssignUri -ErrorAction Stop
        $allAssignments = $allAssignResponse.value

        $auScoped  = $allAssignments | Where-Object { $_.directoryScopeId -ne '/' -and $_.directoryScopeId -notlike '/administrativeUnits/*' -eq $false }
        $dirScoped = $allAssignments | Where-Object { $_.directoryScopeId -eq '/' }

        $auCount  = ($auScoped  | Measure-Object).Count
        $dirCount = ($dirScoped | Measure-Object).Count
        $total    = ($allAssignments | Measure-Object).Count

        $auDetails = $auScoped | ForEach-Object {
            "roleDefId: $($_.roleDefinitionId) → scope: $($_.directoryScopeId)"
        }

        $results.Add((New-CheckResult `
            -CheckId 'PRM-006' `
            -Category 'PrivilegedAccess' `
            -Name 'Role assignment scope (directory vs administrative unit)' `
            -Status 'INFO' `
            -Detail "Total assignments: $total | Directory-scoped (/): $dirCount | Administrative Unit-scoped: $auCount. AU-scoped roles: $($auDetails -join '; ')." `
            -Recommendation 'Use Administrative Units to scope roles to specific subsets of users/devices where possible. This limits blast radius for account compromises.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/admin-units-assign-roles' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $auDetails))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PRM-006' `
            -Category 'PrivilegedAccess' `
            -Name 'Role assignment scope (directory vs administrative unit)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/admin-units-assign-roles' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
