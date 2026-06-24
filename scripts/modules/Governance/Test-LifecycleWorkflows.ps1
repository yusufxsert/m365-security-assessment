#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests Lifecycle Workflows configuration for joiner/leaver automation.

.DESCRIPTION
    Validates whether Lifecycle Workflows are enabled, joiner and leaver workflows
    exist, leaver workflows include critical tasks (disable account, remove access
    package assignments), and checks recent workflow execution history.

.NOTES
    Required Permissions:
        - LifecycleWorkflows.Read.All

    License: Entra ID Governance / Microsoft 365 E5
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
#>

function Test-LifecycleWorkflows {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Task definition IDs for critical leaver tasks
    # Reference: https://learn.microsoft.com/entra/id-governance/lifecycle-workflow-tasks
    $disableUserTaskId              = 'disable-user-account'           # taskDefinitionId pattern
    $removeAccessPackageTaskId      = 'remove-access-package-assignment-for-user'
    $removeGroupMembershipTaskId    = 'remove-user-from-all-groups'
    $disableSignInTaskDef           = '1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950'
    $removeAccessPackageTaskDef     = '4a0b64f2-c7ec-46ba-b117-18f262946c50'

    # -------------------------------------------------------------------------
    # LCW-001: Lifecycle Workflows enabled
    # -------------------------------------------------------------------------
    $workflows = $null

    try {
        $workflowsUri = 'https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows?$top=999'
        $workflowsResponse = Invoke-MgGraphRequest -Method GET -Uri $workflowsUri -ErrorAction Stop
        $workflows = $workflowsResponse.value
        $count = ($workflows | Measure-Object).Count

        if ($count -eq 0) {
            $status = 'MEDIUM'
            $detail = 'Lifecycle Workflows API is accessible but no workflows are configured. Manual onboarding/offboarding processes risk inconsistency and delayed access removal.'
        }
        else {
            $status = 'PASS'
            $detail = "$count Lifecycle Workflow(s) configured."
        }

        $results.Add((New-CheckResult `
            -CheckId 'LCW-001' `
            -Category 'Governance' `
            -Name 'Lifecycle Workflows enabled' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Configure Lifecycle Workflows for joiner (onboarding) and leaver (offboarding) scenarios. Automated workflows reduce the risk of delayed account disabling and access removal when employees leave.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/understanding-lifecycle-workflows' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $isLicense = $_.ToString() -match '(?i)(license|Forbidden|premium|P2|governance)'
        $skipDetail = if ($isLicense) {
            'Check skipped: Entra ID Governance license not available or LifecycleWorkflows.Read.All permission not granted.'
        } else {
            "Check skipped: insufficient permissions. Required: LifecycleWorkflows.Read.All."
        }

        foreach ($checkId in @('LCW-001','LCW-002','LCW-003','LCW-004','LCW-005')) {
            $results.Add((New-CheckResult `
                -CheckId $checkId `
                -Category 'Governance' `
                -Name "Lifecycle Workflow check $checkId" `
                -Status 'INFO' `
                -Detail "$skipDetail Error: $_" `
                -Recommendation 'Grant LifecycleWorkflows.Read.All permission and ensure Entra ID Governance / E5 license.' `
                -Reference 'https://learn.microsoft.com/entra/id-governance/understanding-lifecycle-workflows' `
                -CISControl '' `
                -SC300Domain 'Identity Governance' `
                -LicenseRequired 'E5' `
                -AffectedObjects @()))
        }
        return $results
    }

    # -------------------------------------------------------------------------
    # LCW-002: Joiner workflow configured
    # -------------------------------------------------------------------------
    try {
        $joinerWorkflows = $workflows | Where-Object {
            $_.category -eq 'joiner' -or $_.executionConditions.triggerAndScopeBasedConditions.trigger.'@odata.type' -like '*OnAttributeUpdated*'
        }

        if (($joinerWorkflows | Measure-Object).Count -eq 0) {
            $status = 'MEDIUM'
            $detail = 'No joiner (onboarding) Lifecycle Workflows found. New employees may not have accounts provisioned and access configured automatically.'
        }
        else {
            $joinerNames = ($joinerWorkflows.displayName) -join ', '
            $status = 'PASS'
            $detail = "Joiner workflow(s) found: $joinerNames."
        }

        $results.Add((New-CheckResult `
            -CheckId 'LCW-002' `
            -Category 'Governance' `
            -Name 'Joiner workflow configured (new employee onboarding)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create a joiner Lifecycle Workflow triggered by employee start date. Include tasks: generate TAP (Temporary Access Pass), add to groups/teams, assign access packages, send welcome email. Reduces manual IT onboarding effort and delays.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/tutorial-onboard-custom-workflow-portal' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'LCW-002' `
            -Category 'Governance' `
            -Name 'Joiner workflow configured' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/tutorial-onboard-custom-workflow-portal' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # LCW-003: Leaver workflow configured (offboarding)
    # -------------------------------------------------------------------------
    $leaverWorkflows = $null

    try {
        $leaverWorkflows = $workflows | Where-Object {
            $_.category -eq 'leaver'
        }

        if (($leaverWorkflows | Measure-Object).Count -eq 0) {
            $status = 'HIGH'
            $detail = 'No leaver (offboarding) Lifecycle Workflows found. Accounts of departed employees may not be disabled automatically, creating a persistent access risk.'
        }
        else {
            $leaverNames = ($leaverWorkflows.displayName) -join ', '
            $status = 'PASS'
            $detail = "Leaver workflow(s) found: $leaverNames."
        }

        $results.Add((New-CheckResult `
            -CheckId 'LCW-003' `
            -Category 'Governance' `
            -Name 'Leaver workflow configured (offboarding)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create a leaver Lifecycle Workflow triggered by employee leave date. Include tasks: disable account, revoke sessions, remove group memberships, remove access packages. This ensures timely and consistent offboarding.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/tutorial-offboard-custom-workflow-portal' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'LCW-003' `
            -Category 'Governance' `
            -Name 'Leaver workflow configured' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/tutorial-offboard-custom-workflow-portal' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # LCW-004: Leaver workflow includes account disable + access removal tasks
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $leaverWorkflows -or ($leaverWorkflows | Measure-Object).Count -eq 0) {
            $results.Add((New-CheckResult `
                -CheckId 'LCW-004' `
                -Category 'Governance' `
                -Name 'Leaver workflow includes disable + access removal tasks' `
                -Status 'HIGH' `
                -Detail 'No leaver workflows found — cannot check task completeness.' `
                -Recommendation 'Create a leaver workflow with both disableUser and removeAccessPackageAssignmentForUser tasks.' `
                -Reference 'https://learn.microsoft.com/entra/id-governance/lifecycle-workflow-tasks' `
                -CISControl '' `
                -SC300Domain 'Identity Governance' `
                -LicenseRequired 'E5' `
                -AffectedObjects @()))
        }
        else {
            $incompleteWorkflows = [System.Collections.Generic.List[string]]::new()

            foreach ($leaver in $leaverWorkflows) {
                $workflowId = $leaver.id
                $tasksUri = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/$workflowId/tasks"
                try {
                    $tasksResponse = Invoke-MgGraphRequest -Method GET -Uri $tasksUri -ErrorAction Stop
                    $tasks = $tasksResponse.value
                    $taskDefIds = $tasks.taskDefinitionId

                    # Check for account disable task
                    # taskDefinitionId: 1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950 = disableUser
                    $hasDisableUser = $taskDefIds -contains '1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950'

                    # taskDefinitionId: 4a0b64f2-c7ec-46ba-b117-18f262946c50 = removeAccessPackageAssignmentForUser
                    $hasRemoveAccessPackage = $taskDefIds -contains '4a0b64f2-c7ec-46ba-b117-18f262946c50'

                    $missingTasks = [System.Collections.Generic.List[string]]::new()
                    if (-not $hasDisableUser)         { $missingTasks.Add('disableUser (1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950)') }
                    if (-not $hasRemoveAccessPackage) { $missingTasks.Add('removeAccessPackageAssignmentForUser (4a0b64f2-c7ec-46ba-b117-18f262946c50)') }

                    if ($missingTasks.Count -gt 0) {
                        $incompleteWorkflows.Add("'$($leaver.displayName)' missing tasks: $($missingTasks -join ', ')")
                    }
                }
                catch {
                    $incompleteWorkflows.Add("'$($leaver.displayName)' — could not retrieve tasks: $_")
                }
            }

            if ($incompleteWorkflows.Count -gt 0) {
                $status = 'HIGH'
                $detail = "$($incompleteWorkflows.Count) leaver workflow(s) missing critical tasks: $($incompleteWorkflows -join '; ')."
            }
            else {
                $status = 'PASS'
                $detail = 'All leaver workflows include account disable and access package removal tasks.'
            }

            $results.Add((New-CheckResult `
                -CheckId 'LCW-004' `
                -Category 'Governance' `
                -Name 'Leaver workflow includes disable + access removal tasks' `
                -Status $status `
                -Detail $detail `
                -Recommendation 'Ensure leaver workflows include at minimum: (1) Disable user account (disableUser), (2) Remove access package assignments (removeAccessPackageAssignmentForUser), (3) Remove group memberships, (4) Revoke all sessions. These tasks together ensure complete access termination.' `
                -Reference 'https://learn.microsoft.com/entra/id-governance/lifecycle-workflow-tasks' `
                -CISControl '' `
                -SC300Domain 'Identity Governance' `
                -LicenseRequired 'E5' `
                -AffectedObjects $incompleteWorkflows.ToArray()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'LCW-004' `
            -Category 'Governance' `
            -Name 'Leaver workflow task completeness' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/lifecycle-workflow-tasks' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # LCW-005: Workflow execution history (last 30 days) – INFO
    # -------------------------------------------------------------------------
    try {
        $cutoff = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $executionSummary = [System.Collections.Generic.List[string]]::new()
        $totalRuns = 0
        $failedRuns = 0

        foreach ($workflow in $workflows) {
            $workflowId = $workflow.id
            $runsUri = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/$workflowId/runs?`$filter=startDateTime ge $cutoff&`$top=50"
            try {
                $runsResponse = Invoke-MgGraphRequest -Method GET -Uri $runsUri -ErrorAction Stop
                $runs = $runsResponse.value
                $runCount    = ($runs | Measure-Object).Count
                $failCount   = ($runs | Where-Object { $_.status -in @('failed', 'cancelled') } | Measure-Object).Count
                $successCount= ($runs | Where-Object { $_.status -eq 'completed' } | Measure-Object).Count

                $totalRuns  += $runCount
                $failedRuns += $failCount

                if ($runCount -gt 0) {
                    $executionSummary.Add("'$($workflow.displayName)' (category: $($workflow.category)): $runCount runs | $successCount succeeded | $failCount failed")
                }
                else {
                    $executionSummary.Add("'$($workflow.displayName)' (category: $($workflow.category)): no runs in last 30 days")
                }
            }
            catch {
                $executionSummary.Add("'$($workflow.displayName)': could not retrieve runs — $_")
            }
        }

        $summary = if ($executionSummary.Count -gt 0) { $executionSummary -join ' | ' } else { 'No execution data available.' }

        $results.Add((New-CheckResult `
            -CheckId 'LCW-005' `
            -Category 'Governance' `
            -Name 'Workflow execution history (last 30 days)' `
            -Status 'INFO' `
            -Detail "Total runs (30d): $totalRuns | Failed: $failedRuns. $summary" `
            -Recommendation 'Monitor workflow execution failures regularly. Failed leaver workflows may mean accounts are not disabled as expected. Configure alert notifications for workflow failures.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/lifecycle-workflow-history' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $executionSummary.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'LCW-005' `
            -Category 'Governance' `
            -Name 'Workflow execution history (last 30 days)' `
            -Status 'INFO' `
            -Detail "Could not retrieve workflow execution history. Error: $_" `
            -Recommendation 'Investigate error. Required: LifecycleWorkflows.Read.All.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/lifecycle-workflow-history' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    return $results
}
