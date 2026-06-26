#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests Privileged Identity Management (PIM) configuration for Azure AD roles.

.DESCRIPTION
    Evaluates PIM activation status, role activation settings (MFA, justification,
    duration), eligible vs permanent assignment ratios, and access reviews for
    privileged roles. Requires Entra ID P2 / Microsoft 365 E5 licensing.

.NOTES
    Required Permissions:
        - RoleManagement.Read.All
        - RoleManagementPolicy.Read.AzureAD
        - AccessReview.Read.All

    License: Entra ID P2 / Microsoft 365 E5
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/PrivilegedAccess/Test-PIMRoles.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-PIMRoles {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # PIM-001: PIM activated for Azure AD roles
    # -------------------------------------------------------------------------
    try {
        $eligibleUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=999'
        $eligibleResponse = Invoke-MgGraphRequest -Method GET -Uri $eligibleUri -ErrorAction Stop
        $eligibleSchedules = $eligibleResponse.value

        $permanentUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$top=999'
        $permanentResponse = Invoke-MgGraphRequest -Method GET -Uri $permanentUri -ErrorAction Stop
        # Filter to truly active/permanent (excludes PIM-activated which also appear here)
        $permanentSchedules = $permanentResponse.value | Where-Object {
            $_.assignmentType -eq 'Assigned' -and $_.scheduleInfo.expiration.type -eq 'noExpiration'
        }

        $eligibleCount  = ($eligibleSchedules | Measure-Object).Count
        $permanentCount = ($permanentSchedules | Measure-Object).Count

        if ($eligibleCount -eq 0 -and $permanentCount -gt 2) {
            $status = 'CRITICAL'
            $detail = "PIM is not in use. No eligible role assignments found. $permanentCount permanent (active) assignments detected."
        }
        elseif ($eligibleCount -gt 0 -and $permanentCount -gt $eligibleCount) {
            $status = 'HIGH'
            $detail = "PIM exists but under-utilised. Eligible: $eligibleCount, Permanent: $permanentCount. Most admins still have permanent assignments."
        }
        elseif ($eligibleCount -eq 0 -and $permanentCount -le 2) {
            $status = 'HIGH'
            $detail = "No PIM eligible assignments. Only $permanentCount permanent assignments — likely break-glass accounts only. Verify PIM is configured."
        }
        else {
            $status = 'PASS'
            $detail = "PIM is active. Eligible assignments: $eligibleCount, Permanent (non-PIM) assignments: $permanentCount."
        }

        $results.Add((New-CheckResult `
            -CheckId 'PIM-001' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM activated for Azure AD roles' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Enable PIM and convert all privileged role assignments to Eligible (JIT). Reserve permanent assignments only for break-glass accounts.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-getting-started' `
            -CISControl 'CIS M365 1.1.3' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PIM-001' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM activated for Azure AD roles' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or Entra ID P2 license not available. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All and ensure Entra ID P2 licensing, then re-run.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-getting-started' `
            -CISControl 'CIS M365 1.1.3' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PIM-002: PIM role settings – MFA required on activation
    # -------------------------------------------------------------------------
    try {
        $policiesUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$top=999"
        $policiesResponse = Invoke-MgGraphRequest -Method GET -Uri $policiesUri -ErrorAction Stop
        $policies = $policiesResponse.value

        $noMfaPolicies = [System.Collections.Generic.List[string]]::new()

        foreach ($policy in $policies) {
            $rulesUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$($policy.id)/rules"
            try {
                $rulesResponse = Invoke-MgGraphRequest -Method GET -Uri $rulesUri -ErrorAction Stop
                $rules = $rulesResponse.value

                # Look for enablementRule or authenticationContextRule that enforces MFA
                $mfaRule = $rules | Where-Object {
                    ($_.id -eq 'Enablement_EndUser_Assignment') -or
                    ($_.odataType -eq '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule')
                } | Select-Object -First 1

                if ($mfaRule) {
                    $enabledRules = $mfaRule.enabledRules
                    $hasMfa = ($enabledRules -contains 'MultiFactorAuthentication') -or
                              ($enabledRules -contains 'Justification')
                    if (-not ($enabledRules -contains 'MultiFactorAuthentication')) {
                        $noMfaPolicies.Add($policy.id)
                    }
                }
            }
            catch {
                Write-Verbose "Could not read rules for policy $($policy.id): $_"
            }
        }

        if ($noMfaPolicies.Count -gt 0) {
            $status = 'HIGH'
            $detail = "$($noMfaPolicies.Count) of $($policies.Count) role management policies do not require MFA on activation."
        }
        elseif ($policies.Count -eq 0) {
            $status = 'INFO'
            $detail = 'No role management policies found. PIM may not be configured.'
        }
        else {
            $status = 'PASS'
            $detail = "All $($policies.Count) role management policies require MFA on activation."
        }

        $results.Add((New-CheckResult `
            -CheckId 'PIM-002' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM role settings – MFA required on activation' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'In PIM role settings, enable "Require multifactor authentication on activation" for all privileged roles.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings' `
            -CISControl 'CIS M365 1.1.1' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $noMfaPolicies.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PIM-002' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM role settings – MFA required on activation' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagementPolicy.Read.AzureAD. Error: $_" `
            -Recommendation 'Grant RoleManagementPolicy.Read.AzureAD permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings' `
            -CISControl 'CIS M365 1.1.1' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PIM-003: PIM role settings – justification required on activation
    # -------------------------------------------------------------------------
    try {
        $policiesUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$top=999"
        $policiesResponse = Invoke-MgGraphRequest -Method GET -Uri $policiesUri -ErrorAction Stop
        $policies = $policiesResponse.value

        $noJustificationPolicies = [System.Collections.Generic.List[string]]::new()

        foreach ($policy in $policies) {
            $rulesUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$($policy.id)/rules"
            try {
                $rulesResponse = Invoke-MgGraphRequest -Method GET -Uri $rulesUri -ErrorAction Stop
                $rules = $rulesResponse.value

                $enablementRule = $rules | Where-Object {
                    $_.id -eq 'Enablement_EndUser_Assignment'
                } | Select-Object -First 1

                if ($enablementRule) {
                    $enabledRules = $enablementRule.enabledRules
                    if (-not ($enabledRules -contains 'Justification')) {
                        $noJustificationPolicies.Add($policy.id)
                    }
                }
            }
            catch {
                Write-Verbose "Could not read rules for policy $($policy.id): $_"
            }
        }

        if ($noJustificationPolicies.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$($noJustificationPolicies.Count) of $($policies.Count) role management policies do not require justification on activation."
        }
        elseif ($policies.Count -eq 0) {
            $status = 'INFO'
            $detail = 'No role management policies found.'
        }
        else {
            $status = 'PASS'
            $detail = "All $($policies.Count) role management policies require justification on activation."
        }

        $results.Add((New-CheckResult `
            -CheckId 'PIM-003' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM role settings – justification required on activation' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'In PIM role settings, enable "Require justification on activation" for all privileged roles to create an audit trail.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $noJustificationPolicies.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PIM-003' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM role settings – justification required on activation' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagementPolicy.Read.AzureAD. Error: $_" `
            -Recommendation 'Grant RoleManagementPolicy.Read.AzureAD permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PIM-004: PIM activation duration settings (max hours)
    # -------------------------------------------------------------------------
    try {
        # Global Administrator role definition ID (well-known)
        $gaRoleDefId = '62e90394-69f5-4237-9190-012177145e10'

        # Get policies for Global Admin
        $assignmentsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '$gaRoleDefId'&`$top=1"
        $assignmentResponse = Invoke-MgGraphRequest -Method GET -Uri $assignmentsUri -ErrorAction Stop

        # Retrieve the policy assignment for GA to find the policy ID
        $policyAssignUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$gaRoleDefId'"
        $policyAssignResponse = Invoke-MgGraphRequest -Method GET -Uri $policyAssignUri -ErrorAction Stop
        $policyAssignments = $policyAssignResponse.value

        $longDurationRoles = [System.Collections.Generic.List[string]]::new()

        foreach ($pa in $policyAssignments) {
            $policyId = $pa.policyId
            $rulesUri = "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$policyId/rules"
            $rulesResponse = Invoke-MgGraphRequest -Method GET -Uri $rulesUri -ErrorAction Stop
            $rules = $rulesResponse.value

            # Look for expiration rule for active assignment
            $expirationRule = $rules | Where-Object {
                $_.id -eq 'Expiration_EndUser_Assignment'
            } | Select-Object -First 1

            if ($expirationRule) {
                $maxDuration = $expirationRule.maximumDuration
                # Duration is ISO 8601 (PT8H = 8 hours, PT24H = 24 hours, P1D = 1 day)
                if ($maxDuration -match 'PT(\d+)H') {
                    $hours = [int]$Matches[1]
                    if ($hours -gt 8) {
                        $longDurationRoles.Add("Policy $policyId (roleDefId: $($pa.roleDefinitionId)): ${hours}h max activation")
                    }
                }
                elseif ($maxDuration -match 'P(\d+)D') {
                    $days = [int]$Matches[1]
                    $longDurationRoles.Add("Policy $policyId (roleDefId: $($pa.roleDefinitionId)): ${days}d max activation")
                }
            }
        }

        if ($longDurationRoles.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "Global Administrator role allows activation duration > 8 hours: $($longDurationRoles -join '; ')"
        }
        else {
            $status = 'PASS'
            $detail = 'Global Administrator PIM activation duration is 8 hours or less.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'PIM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM activation duration (max hours)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Set maximum PIM activation duration to 8 hours or less for Global Administrator. Use shorter durations (1-4h) where operationally feasible.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $longDurationRoles.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PIM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM activation duration (max hours)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or PIM not configured. Required: RoleManagementPolicy.Read.AzureAD. Error: $_" `
            -Recommendation 'Grant RoleManagementPolicy.Read.AzureAD permission and ensure PIM is configured for Global Administrator.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PIM-005: Eligible vs permanent assignment ratio (INFO)
    # -------------------------------------------------------------------------
    try {
        $eligibleUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?$top=999'
        $eligibleResponse = Invoke-MgGraphRequest -Method GET -Uri $eligibleUri -ErrorAction Stop
        $eligibleCount = ($eligibleResponse.value | Measure-Object).Count

        $permanentUri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$top=999'
        $permanentResponse = Invoke-MgGraphRequest -Method GET -Uri $permanentUri -ErrorAction Stop
        $permanentSchedules = $permanentResponse.value | Where-Object {
            $_.assignmentType -eq 'Assigned' -and $_.scheduleInfo.expiration.type -eq 'noExpiration'
        }
        $permanentCount = ($permanentSchedules | Measure-Object).Count

        $total = $eligibleCount + $permanentCount
        $eligiblePct = if ($total -gt 0) { [math]::Round(($eligibleCount / $total) * 100, 1) } else { 0 }

        $results.Add((New-CheckResult `
            -CheckId 'PIM-005' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM eligible vs permanent assignment ratio' `
            -Status 'INFO' `
            -Detail "Eligible (JIT): $eligibleCount | Permanent (active): $permanentCount | Total: $total | Eligible ratio: $eligiblePct%." `
            -Recommendation 'Target: >80% of privileged role assignments should be Eligible (JIT via PIM). Permanent assignments should be break-glass accounts only.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-getting-started' `
            -CISControl 'CIS M365 1.1.3' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PIM-005' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM eligible vs permanent assignment ratio' `
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
    # PIM-006: PIM access reviews for privileged roles
    # -------------------------------------------------------------------------
    try {
        $reviewsUri = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=999'
        $reviewsResponse = Invoke-MgGraphRequest -Method GET -Uri $reviewsUri -ErrorAction Stop
        $allReviews = $reviewsResponse.value

        # Filter for role-scoped reviews
        $roleReviews = $allReviews | Where-Object {
            $_.scope.query -like '*/roleAssignments*' -or
            $_.scope.'@odata.type' -eq '#microsoft.graph.principalResourceMembershipsScope' -or
            ($_.scope.principalScopes | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.accessReviewQueryScope' -and $_.query -like '*roleEligibilitySchedule*' })
        }

        # Check specifically for GA and Privileged Role Admin reviews
        $gaRoleDefId   = '62e90394-69f5-4237-9190-012177145e10'
        $praRoleDefId  = 'e8611ab8-c189-46e8-94e1-60213ab1f814'

        $gaReview  = $roleReviews | Where-Object { ($_ | ConvertTo-Json -Depth 10) -match $gaRoleDefId }
        $praReview = $roleReviews | Where-Object { ($_ | ConvertTo-Json -Depth 10) -match $praRoleDefId }

        $missingReviews = [System.Collections.Generic.List[string]]::new()
        if (-not $gaReview)  { $missingReviews.Add('Global Administrator') }
        if (-not $praReview) { $missingReviews.Add('Privileged Role Administrator') }

        if ($missingReviews.Count -gt 0) {
            $status = 'HIGH'
            $detail = "No access reviews found for: $($missingReviews -join ', '). Total role-scoped reviews: $($roleReviews.Count). Total reviews: $($allReviews.Count)."
        }
        elseif ($roleReviews.Count -eq 0) {
            $status = 'HIGH'
            $detail = "No access reviews configured for any privileged roles. Total reviews: $($allReviews.Count)."
        }
        else {
            $status = 'PASS'
            $detail = "Access reviews exist for Global Administrator and Privileged Role Administrator. Role-scoped reviews: $($roleReviews.Count)."
        }

        $results.Add((New-CheckResult `
            -CheckId 'PIM-006' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM access reviews for privileged roles' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Configure quarterly access reviews for Global Administrator and Privileged Role Administrator roles. Set auto-remediation to deny on no response.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review' `
            -CISControl 'CIS M365 1.1.4' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $missingReviews.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PIM-006' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM access reviews for privileged roles' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: AccessReview.Read.All. Error: $_" `
            -Recommendation 'Grant AccessReview.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review' `
            -CISControl 'CIS M365 1.1.4' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    return $results
}
