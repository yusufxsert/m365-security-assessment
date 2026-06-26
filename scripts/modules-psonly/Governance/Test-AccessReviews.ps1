#Requires -Version 7.0

<#
.SYNOPSIS
    Tests Access Review configuration across the Microsoft 365 tenant. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgIdentityGovernanceAccessReviewDefinition and
    Get-MgIdentityGovernanceAccessReviewDefinitionInstance instead of raw
    Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    The Microsoft.Graph.Identity.Governance module provides strongly-typed cmdlets
    with automatic pagination for access review objects. The -All parameter handles
    server-side paging without manual nextLink tracking.

    SEE ALSO (Graph variant):
        scripts/modules/Governance/Test-AccessReviews.ps1

    Required connection:
        Connect-MgGraph -Scopes "AccessReview.Read.All"

    Required scopes:
        AccessReview.Read.All

    Required modules:
        Microsoft.Graph.Identity.Governance

    License: Entra ID P2 / Microsoft 365 E5
    SC-300 Domain: Identity Governance

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-AccessReviews {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Well-known role IDs for review coverage check
    $gaRoleDefId  = '62e90394-69f5-4237-9190-012177145e10'
    $praRoleDefId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'

    # Retrieve all access review definitions once
    $allReviews = $null

    try {
        $allReviews = Get-MgIdentityGovernanceAccessReviewDefinition -All -ErrorAction Stop
    }
    catch {
        $isLicense = $_.ToString() -match '(?i)(license|Forbidden|premium|P2|governance)'
        $skipDetail = if ($isLicense) {
            'Check skipped: Entra ID P2 license not available or AccessReview.Read.All permission not granted.'
        } else {
            'Check skipped: insufficient permissions. Required: AccessReview.Read.All.'
        }

        foreach ($checkId in @('ARV-001','ARV-002','ARV-003','ARV-004','ARV-005','ARV-006')) {
            $results.Add((New-CheckResult `
                -CheckId $checkId `
                -Category 'Governance' `
                -Name "Access Review check $checkId" `
                -Status 'INFO' `
                -Detail "$skipDetail Error: $_" `
                -Recommendation 'Connect-MgGraph -Scopes "AccessReview.Read.All". Ensure Entra ID P2 / E5 licensing.' `
                -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
                -CISControl '' `
                -SC300Domain 'Identity Governance' `
                -LicenseRequired 'E5' `
                -AffectedObjects @()))
        }
        return $results
    }

    # -------------------------------------------------------------------------
    # ARV-001: Access reviews configured (any)
    # -------------------------------------------------------------------------
    $count = ($allReviews | Measure-Object).Count

    if ($count -eq 0) {
        $status = 'HIGH'
        $detail = 'No access reviews are configured. This means guest access, privileged role assignments, and group memberships are never periodically reviewed.'
    }
    else {
        $status = 'PASS'
        $detail = "$count access review definition(s) configured."
    }

    $results.Add((New-CheckResult `
        -CheckId 'ARV-001' `
        -Category 'Governance' `
        -Name 'Access reviews configured' `
        -Status $status `
        -Detail $detail `
        -Recommendation 'Configure access reviews for at minimum: (1) Guest/external user group memberships, (2) Global Administrator and privileged roles, (3) High-privilege group memberships.' `
        -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
        -CISControl 'CIS M365 1.1.4' `
        -SC300Domain 'Identity Governance' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # ARV-002: Access reviews for guest users
    # -------------------------------------------------------------------------
    try {
        $guestReviews = $allReviews | Where-Object {
            $scopeJson = $_ | ConvertTo-Json -Depth 10
            $scopeJson -match '(?i)(guestUser|externalUser|guest)'
        }

        if (($guestReviews | Measure-Object).Count -eq 0) {
            $status = 'HIGH'
            $detail = 'No access reviews configured for guest/external users. Guest accounts accumulate over time without reviews, creating stale external access.'
        }
        else {
            $status = 'PASS'
            $detail = "$($guestReviews.Count) access review(s) targeting guest users found."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ARV-002' `
            -Category 'Governance' `
            -Name 'Access reviews for guest users' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create a recurring access review (quarterly) for all guest users across Microsoft 365 groups and Teams. Configure auto-removal of guests who are not approved by the review owner.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-external-users' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ARV-002' `
            -Category 'Governance' `
            -Name 'Access reviews for guest users' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-external-users' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ARV-003: Access reviews for privileged roles (GA + PRA)
    # -------------------------------------------------------------------------
    try {
        $roleReviews = $allReviews | Where-Object {
            $reviewJson = $_ | ConvertTo-Json -Depth 10
            $reviewJson -match '(?i)(roleEligibilitySchedule|roleAssignment|roleDefinition|roleManagement)'
        }

        $gaReview  = $roleReviews | Where-Object { ($_ | ConvertTo-Json -Depth 10) -match $gaRoleDefId }
        $praReview = $roleReviews | Where-Object { ($_ | ConvertTo-Json -Depth 10) -match $praRoleDefId }

        $missingRoles = [System.Collections.Generic.List[string]]::new()
        if (-not $gaReview)  { $missingRoles.Add('Global Administrator') }
        if (-not $praReview) { $missingRoles.Add('Privileged Role Administrator') }

        if ($missingRoles.Count -gt 0) {
            $status = 'HIGH'
            $detail = "No access reviews found for: $($missingRoles -join ', '). Role-scoped reviews found: $(($roleReviews | Measure-Object).Count)."
        }
        else {
            $status = 'PASS'
            $detail = "Access reviews exist for Global Administrator and Privileged Role Administrator. Role reviews total: $(($roleReviews | Measure-Object).Count)."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ARV-003' `
            -Category 'Governance' `
            -Name 'Access reviews for privileged roles' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Configure quarterly access reviews for Global Administrator and Privileged Role Administrator. Set auto-removal for unresponsive reviewers.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review' `
            -CISControl 'CIS M365 1.1.4' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $missingRoles.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ARV-003' `
            -Category 'Governance' `
            -Name 'Access reviews for privileged roles' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review' `
            -CISControl 'CIS M365 1.1.4' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ARV-004: Access review completion rate
    # Uses Get-MgIdentityGovernanceAccessReviewDefinitionInstance
    # -------------------------------------------------------------------------
    try {
        $completedCount = 0
        $totalInstances = 0
        $lowCompletionReviews = [System.Collections.Generic.List[string]]::new()

        foreach ($review in $allReviews) {
            $instances = Get-MgIdentityGovernanceAccessReviewDefinitionInstance `
                -AccessReviewScheduleDefinitionId $review.Id `
                -All `
                -ErrorAction SilentlyContinue

            if (-not $instances) { continue }

            foreach ($instance in $instances) {
                $totalInstances++
                if ($instance.Status -in @('Completed', 'AutoReviewed')) {
                    $completedCount++
                }
            }

            $reviewInstances  = ($instances | Measure-Object).Count
            if ($reviewInstances -gt 0) {
                $reviewCompleted  = ($instances | Where-Object { $_.Status -in @('Completed','AutoReviewed') } | Measure-Object).Count
                $reviewCompletionRate = [math]::Round(($reviewCompleted / $reviewInstances) * 100, 0)
                if ($reviewCompletionRate -lt 80 -and $reviewInstances -ge 2) {
                    $lowCompletionReviews.Add("'$($review.DisplayName)': $reviewCompletionRate% ($reviewCompleted/$reviewInstances instances completed)")
                }
            }
        }

        $overallRate = if ($totalInstances -gt 0) {
            [math]::Round(($completedCount / $totalInstances) * 100, 1)
        } else { 0 }

        if ($lowCompletionReviews.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "Reviews with <80% completion rate: $($lowCompletionReviews -join '; '). Overall: $completedCount/$totalInstances instances completed ($overallRate%)."
        }
        elseif ($totalInstances -eq 0) {
            $status = 'INFO'
            $detail = 'No access review instances found. Reviews may be newly created or have not yet triggered.'
        }
        else {
            $status = 'PASS'
            $detail = "All access review instances have >=80% completion rate. Overall: $completedCount/$totalInstances ($overallRate%)."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ARV-004' `
            -Category 'Governance' `
            -Name 'Access review completion rate' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Investigate reviews with low completion rates. Send reminders to reviewers before deadline. Consider enabling auto-remediation (deny on no response).' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $lowCompletionReviews.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ARV-004' `
            -Category 'Governance' `
            -Name 'Access review completion rate' `
            -Status 'INFO' `
            -Detail "Check failed: could not retrieve review instances. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ARV-005: Auto-remediation on no response (defaultDecision != None)
    # -------------------------------------------------------------------------
    try {
        $noAutoRemediationReviews = [System.Collections.Generic.List[string]]::new()

        foreach ($review in $allReviews) {
            $settings = $review.Settings
            if ($null -ne $settings) {
                $defaultDecision = $settings.DefaultDecision
                if ($defaultDecision -eq 'None' -or $null -eq $defaultDecision) {
                    $noAutoRemediationReviews.Add("'$($review.DisplayName)' — defaultDecision: $($defaultDecision ?? 'not set')")
                }
            }
        }

        if ($noAutoRemediationReviews.Count -gt 0) {
            $status = 'HIGH'
            $detail = "$($noAutoRemediationReviews.Count) access review(s) have no auto-remediation on non-response (defaultDecision = None): $($noAutoRemediationReviews -join '; ')."
        }
        else {
            $status = 'PASS'
            $detail = 'All access reviews have auto-remediation configured on reviewer non-response.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ARV-005' `
            -Category 'Governance' `
            -Name 'Auto-remediation on no response configured' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Set defaultDecision to "Deny" on all access reviews, especially for privileged roles and guest access. This ensures access is revoked when reviewers fail to respond.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview#settings' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $noAutoRemediationReviews.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ARV-005' `
            -Category 'Governance' `
            -Name 'Auto-remediation on no response configured' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview#settings' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ARV-006: Access review recurrence – privileged role reviews not annual
    # -------------------------------------------------------------------------
    try {
        $roleReviews = $allReviews | Where-Object {
            $reviewJson = $_ | ConvertTo-Json -Depth 10
            $reviewJson -match '(?i)(roleEligibilitySchedule|roleAssignment|roleDefinition|roleManagement)'
        }

        $annualOrLessRoleReviews = [System.Collections.Generic.List[string]]::new()

        foreach ($review in $roleReviews) {
            $recurrence = $review.Settings.Recurrence
            if ($recurrence) {
                $pattern = $recurrence.Pattern
                $isAnnualOrLess = (
                    ($pattern.Type -eq 'absoluteYearly') -or
                    ($pattern.Type -eq 'absoluteMonthly' -and [int]$pattern.Interval -ge 12) -or
                    ($null -eq $pattern)
                )
                if ($isAnnualOrLess) {
                    $intervalDesc = if ($pattern) { "$($pattern.Type) (interval: $($pattern.Interval))" } else { 'one-time' }
                    $annualOrLessRoleReviews.Add("'$($review.DisplayName)' — recurrence: $intervalDesc")
                }
            }
            else {
                $annualOrLessRoleReviews.Add("'$($review.DisplayName)' — no recurrence (one-time)")
            }
        }

        if ($annualOrLessRoleReviews.Count -gt 0) {
            $status = 'LOW'
            $detail = "$($annualOrLessRoleReviews.Count) privileged role review(s) run annually or less: $($annualOrLessRoleReviews -join '; '). Annual reviews are insufficient for privileged role governance."
        }
        elseif (($roleReviews | Measure-Object).Count -eq 0) {
            $status = 'INFO'
            $detail = 'No role-scoped access reviews found to evaluate recurrence.'
        }
        else {
            $status = 'PASS'
            $detail = 'All privileged role reviews run more frequently than annually (quarterly or monthly).'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ARV-006' `
            -Category 'Governance' `
            -Name 'Access review recurrence – privileged roles' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Configure privileged role access reviews to run quarterly (every 3 months) or monthly for high-sensitivity roles (Global Administrator, Privileged Role Administrator).' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $annualOrLessRoleReviews.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ARV-006' `
            -Category 'Governance' `
            -Name 'Access review recurrence – privileged roles' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-create-roles-and-resource-roles-review' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    return $results
}
