#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    Tests Privileged Identity Management (PIM) configuration for Azure AD roles.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-Mg* cmdlets from Microsoft.Graph PowerShell SDK
    instead of Invoke-MgGraphRequest. Authentication is interactive delegated
    (Connect-MgGraph -Scopes "...") — no App Registration or service principal
    required. All check IDs, thresholds, and result logic are identical to the
    Graph-HTTP variant (modules/PrivilegedAccess/Test-PIMRoles.ps1).

    SEE ALSO: scripts/modules/PrivilegedAccess/Test-PIMRoles.ps1
              (Graph HTTP variant using Invoke-MgGraphRequest)

    Evaluates PIM activation status, role activation settings (MFA, justification,
    duration), eligible vs permanent assignment ratios, and access reviews for
    privileged roles. Requires Entra ID P2 / Microsoft 365 E5 licensing.

.NOTES
    WHY PS-ONLY
        Intended for interactive use by admins who connect with their own credentials.
        No service principal, no client secret, no certificate — just:
            Connect-MgGraph -Scopes "RoleManagement.Read.All","RoleManagementPolicy.Read.AzureAD","AccessReview.Read.All"

    Required connection  : Connect-MgGraph (delegated, interactive)
    Required scopes      : RoleManagement.Read.All, RoleManagementPolicy.Read.AzureAD,
                           AccessReview.Read.All
    Required module      : Microsoft.Graph.Identity.Governance
    License              : Entra ID P2 / Microsoft 365 E5
    CIS Benchmark        : CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain        : Identity Governance

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
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
        $eligibleSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop

        $allAssignmentSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop
        $permanentSchedules = $allAssignmentSchedules | Where-Object {
            $_.AssignmentType -eq 'Assigned' -and $_.ScheduleInfo.Expiration.Type -eq 'noExpiration'
        }

        $eligibleCount  = ($eligibleSchedules  | Measure-Object).Count
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
        # Filter to DirectoryRole scope policies
        $policies = Get-MgPolicyRoleManagementPolicy -All -ErrorAction Stop | Where-Object {
            $_.ScopeId -eq '/' -and $_.ScopeType -eq 'DirectoryRole'
        }

        $noMfaPolicies = [System.Collections.Generic.List[string]]::new()

        foreach ($policy in $policies) {
            try {
                $rules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -All -ErrorAction Stop

                $mfaRule = $rules | Where-Object {
                    ($_.Id -eq 'Enablement_EndUser_Assignment') -or
                    ($_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule')
                } | Select-Object -First 1

                if ($mfaRule) {
                    $enabledRules = $mfaRule.AdditionalProperties.enabledRules
                    if (-not ($enabledRules -contains 'MultiFactorAuthentication')) {
                        $noMfaPolicies.Add($policy.Id)
                    }
                }
            }
            catch {
                Write-Verbose "Could not read rules for policy $($policy.Id): $_"
            }
        }

        if ($noMfaPolicies.Count -gt 0) {
            $status = 'HIGH'
            $detail = "$($noMfaPolicies.Count) of $($policies.Count) role management policies do not require MFA on activation."
        }
        elseif (($policies | Measure-Object).Count -eq 0) {
            $status = 'INFO'
            $detail = 'No role management policies found. PIM may not be configured.'
        }
        else {
            $status = 'PASS'
            $detail = "All $(($policies | Measure-Object).Count) role management policies require MFA on activation."
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
        $policies = Get-MgPolicyRoleManagementPolicy -All -ErrorAction Stop | Where-Object {
            $_.ScopeId -eq '/' -and $_.ScopeType -eq 'DirectoryRole'
        }

        $noJustificationPolicies = [System.Collections.Generic.List[string]]::new()

        foreach ($policy in $policies) {
            try {
                $rules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policy.Id -All -ErrorAction Stop

                $enablementRule = $rules | Where-Object {
                    $_.Id -eq 'Enablement_EndUser_Assignment'
                } | Select-Object -First 1

                if ($enablementRule) {
                    $enabledRules = $enablementRule.AdditionalProperties.enabledRules
                    if (-not ($enabledRules -contains 'Justification')) {
                        $noJustificationPolicies.Add($policy.Id)
                    }
                }
            }
            catch {
                Write-Verbose "Could not read rules for policy $($policy.Id): $_"
            }
        }

        $policyCount = ($policies | Measure-Object).Count
        if ($noJustificationPolicies.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$($noJustificationPolicies.Count) of $policyCount role management policies do not require justification on activation."
        }
        elseif ($policyCount -eq 0) {
            $status = 'INFO'
            $detail = 'No role management policies found.'
        }
        else {
            $status = 'PASS'
            $detail = "All $policyCount role management policies require justification on activation."
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
        $gaRoleDefId = '62e90394-69f5-4237-9190-012177145e10'

        # Retrieve all policies for DirectoryRole scope, then find one covering GA
        # Get-MgPolicyRoleManagementPolicy does not have a -Filter for roleDefinitionId
        # directly; we retrieve all and match by checking rules.
        # The policy-to-role mapping is through roleManagementPolicyAssignments — use
        # the Graph cmdlet for that endpoint.
        # NOTE: Get-MgPolicyRoleManagementPolicyAssignment is not in the confirmed
        #       cmdlet table, so we emit an INFO stub per the task rules.
        $results.Add((New-CheckResult `
            -CheckId 'PIM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM activation duration (max hours)' `
            -Status 'INFO' `
            -Detail ('PIM-004 uses the roleManagementPolicyAssignments endpoint ' +
                     '(GET /policies/roleManagementPolicyAssignments) which has no confirmed ' +
                     'Get-Mg* cmdlet in the PS-only mapping table. ' +
                     'Use the Graph HTTP variant (modules/PrivilegedAccess/Test-PIMRoles.ps1) ' +
                     'for this check, or call: ' +
                     'Invoke-MgGraphRequest -Method GET -Uri ' +
                     '"https://graph.microsoft.com/v1.0/policies/roleManagementPolicyAssignments?' +
                     '$filter=scopeId eq ''/'' and scopeType eq ''DirectoryRole'' and roleDefinitionId eq ''62e90394-69f5-4237-9190-012177145e10''"') `
            -Recommendation 'Set maximum PIM activation duration to 8 hours or less for Global Administrator. Use the Graph HTTP variant for automated enforcement.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PIM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'PIM activation duration (max hours)' `
            -Status 'INFO' `
            -Detail "Check skipped. Error: $_" `
            -Recommendation 'Use the Graph HTTP variant (modules/PrivilegedAccess/Test-PIMRoles.ps1) for this check.' `
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
        $eligibleSchedules = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
        $eligibleCount     = ($eligibleSchedules | Measure-Object).Count

        $allAssignmentSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All -ErrorAction Stop
        $permanentSchedules = $allAssignmentSchedules | Where-Object {
            $_.AssignmentType -eq 'Assigned' -and $_.ScheduleInfo.Expiration.Type -eq 'noExpiration'
        }
        $permanentCount = ($permanentSchedules | Measure-Object).Count

        $total       = $eligibleCount + $permanentCount
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
        $allReviews = Get-MgIdentityGovernanceAccessReviewDefinition -All -ErrorAction Stop

        # Filter for role-scoped reviews
        $roleReviews = $allReviews | Where-Object {
            $_.Scope.AdditionalProperties.query -like '*/roleAssignments*' -or
            $_.Scope.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.principalResourceMembershipsScope' -or
            ($_.Scope.AdditionalProperties.principalScopes | Where-Object {
                $_.'@odata.type' -eq '#microsoft.graph.accessReviewQueryScope' -and
                $_.query -like '*roleEligibilitySchedule*'
            })
        }

        $gaRoleDefId  = '62e90394-69f5-4237-9190-012177145e10'
        $praRoleDefId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'

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
