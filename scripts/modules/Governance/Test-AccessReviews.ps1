#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests Access Review configuration across the Microsoft 365 tenant.

.DESCRIPTION
    Validates that access reviews are configured for guest users, privileged roles,
    and other groups. Checks completion rates, auto-remediation configuration,
    review scope, and recurrence frequency.

.NOTES
    Required Permissions:
        - AccessReview.Read.All

    License: Entra ID P2 / Microsoft 365 E5
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
#>

function Test-AccessReviews {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Well-known role IDs used for role review coverage check
    $gaRoleDefId  = '62e90394-69f5-4237-9190-012177145e10'
    $praRoleDefId = 'e8611ab8-c189-46e8-94e1-60213ab1f814'

    # Retrieve all access review definitions once
    $allReviews = $null

    try {
        $reviewsUri = 'https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions?$top=999'
        $reviewsResponse = Invoke-MgGraphRequest -Method GET -Uri $reviewsUri -ErrorAction Stop
        $allReviews = $reviewsResponse.value
    }
    catch {
        $isLicense = $_.ToString() -match '(?i)(license|Forbidden|premium|P2|governance)'
        $skipDetail = if ($isLicense) {
            'Check skipped: Entra ID P2 license not available or AccessReview.Read.All permission not granted.'
        } else {
            "Check skipped: insufficient permissions. Required: AccessReview.Read.All."
        }

        # Emit a single INFO for all checks and return
        foreach ($checkId in @('ARV-001','ARV-002','ARV-003','ARV-004','ARV-005','ARV-006')) {
            $results.Add((New-CheckResult `
                -CheckId $checkId `
                -Category 'Governance' `
                -Name "Access Review check $checkId" `
                -Status 'INFO' `
                -Detail "$skipDetail Error: $_" `
                -Recommendation 'Grant AccessReview.Read.All permission and ensure Entra ID P2 / E5 licensing.' `
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
        -Recommendation 'Configure access reviews for at minimum: (1) Guest/external user group memberships, (2) Global Administrator and privileged roles, (3) High-privilege group memberships. Use Entra ID Governance or the Access Reviews feature in Entra ID P2.' `
        -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
        -CISControl 'CIS M365 1.1.4' `
        -SC300Domain 'Identity Governance' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # ARV-002: Access reviews for guest users
    # -------------------------------------------------------------------------
    try {
        # Filter for guest-scoped reviews
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
            -Recommendation 'Configure quarterly access reviews for Global Administrator and Privileged Role Administrator. Set auto-removal for unresponsive reviewers. PIM role reviews can be configured directly in PIM settings per role.' `
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
    # -------------------------------------------------------------------------
    try {
        $completedCount = 0
        $totalInstances = 0
        $lowCompletionReviews = [System.Collections.Generic.List[string]]::new()

        foreach ($review in $allReviews) {
            $reviewId = $review.id
            $instancesUri = "https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions/$reviewId/instances?`$top=10&`$orderby=startDateTime desc"
            try {
                $instancesResponse = Invoke-MgGraphRequest -Method GET -Uri $instancesUri -ErrorAction Stop
                $instances = $instancesResponse.value

                foreach ($instance in $instances) {
                    $totalInstances++
                    if ($instance.status -in @('Completed', 'AutoReviewed')) {
                        $completedCount++
                    }
                }

                # Per-review completion rate for recent instances
                $reviewInstances = ($instances | Measure-Object).Count
                if ($reviewInstances -gt 0) {
                    $reviewCompleted = ($instances | Where-Object { $_.status -in @('Completed','AutoReviewed') } | Measure-Object).Count
                    $reviewCompletionRate = [math]::Round(($reviewCompleted / $reviewInstances) * 100, 0)
                    if ($reviewCompletionRate -lt 80 -and $reviewInstances -ge 2) {
                        $lowCompletionReviews.Add("'$($review.displayName)': $reviewCompletionRate% ($reviewCompleted/$reviewInstances instances completed)")
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve instances for review $reviewId: $_"
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
            $detail = "All access review instances have ≥80% completion rate. Overall: $completedCount/$totalInstances ($overallRate%)."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ARV-004' `
            -Category 'Governance' `
            -Name 'Access review completion rate' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Investigate reviews with low completion rates. Send reminders to reviewers before deadline. Consider enabling auto-remediation (deny on no response) to ensure stale access is removed even when reviewers are unresponsive.' `
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
            $settings = $review.settings
            if ($null -ne $settings) {
                $defaultDecision = $settings.defaultDecision
                # 'None' means no action is taken when reviewer doesn't respond
                if ($defaultDecision -eq 'None' -or $null -eq $defaultDecision) {
                    $noAutoRemediationReviews.Add("'$($review.displayName)' — defaultDecision: $($defaultDecision ?? 'not set')")
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
            -Recommendation 'Set defaultDecision to "Deny" on all access reviews, especially for privileged roles and guest access. This ensures that access is revoked when reviewers fail to respond, preventing stale access from persisting.' `
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
            $recurrence = $review.settings.recurrence
            if ($recurrence) {
                $pattern = $recurrence.pattern
                $range   = $recurrence.range

                # Check if it's annual: type = absoluteYearly or monthly with interval 12
                $isAnnualOrLess = (
                    ($pattern.type -eq 'absoluteYearly') -or
                    ($pattern.type -eq 'absoluteMonthly' -and [int]$pattern.interval -ge 12) -or
                    ($null -eq $pattern) # No recurrence = one-time review
                )

                if ($isAnnualOrLess) {
                    $intervalDesc = if ($pattern) { "$($pattern.type) (interval: $($pattern.interval))" } else { 'one-time' }
                    $annualOrLessRoleReviews.Add("'$($review.displayName)' — recurrence: $intervalDesc")
                }
            }
            else {
                # No recurrence settings = one-time review
                $annualOrLessRoleReviews.Add("'$($review.displayName)' — no recurrence (one-time)")
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
            -Recommendation 'Configure privileged role access reviews to run quarterly (every 3 months) or monthly for high-sensitivity roles (Global Administrator, Privileged Role Administrator). Annual reviews leave too large a window for stale privileged access.' `
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
