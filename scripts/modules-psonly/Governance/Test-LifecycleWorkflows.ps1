#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.Governance

<#
.SYNOPSIS
    Tests Lifecycle Workflows configuration for joiner/leaver automation. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgIdentityGovernanceLifecycleWorkflow and related
    cmdlets from Microsoft.Graph.Identity.Governance instead of raw
    Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    The Microsoft.Graph.Identity.Governance module wraps the
    /identityGovernance/lifecycleWorkflows path with strongly-typed cmdlets.
    Workflow tasks and run history are accessible via:
      - Get-MgIdentityGovernanceLifecycleWorkflowTask
      - Get-MgIdentityGovernanceLifecycleWorkflowRun (if available in module version)

    NOTE on workflow runs:
    Get-MgIdentityGovernanceLifecycleWorkflowRun requires module version >= 2.x.
    If unavailable, the run history check (LCW-005) will emit INFO with guidance.

    SEE ALSO (Graph variant):
        scripts/modules/Governance/Test-LifecycleWorkflows.ps1

    Required connection:
        Connect-MgGraph -Scopes "LifecycleWorkflows.Read.All"

    Required scopes:
        LifecycleWorkflows.Read.All

    Required modules:
        Microsoft.Graph.Identity.Governance

    License: Entra ID Governance / Microsoft 365 E5
    SC-300 Domain: Identity Governance

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-LifecycleWorkflows {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Task definition IDs for critical leaver tasks
    $disableSignInTaskDef       = '1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950'  # disableUser
    $removeAccessPackageTaskDef = '4a0b64f2-c7ec-46ba-b117-18f262946c50'  # removeAccessPackageAssignmentForUser

    # -------------------------------------------------------------------------
    # LCW-001: Lifecycle Workflows enabled
    # -------------------------------------------------------------------------
    $workflows = $null

    try {
        $workflows = Get-MgIdentityGovernanceLifecycleWorkflow -All -ErrorAction Stop
        $count     = ($workflows | Measure-Object).Count

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
            'Check skipped: insufficient permissions. Required: LifecycleWorkflows.Read.All.'
        }

        foreach ($checkId in @('LCW-001','LCW-002','LCW-003','LCW-004','LCW-005')) {
            $results.Add((New-CheckResult `
                -CheckId $checkId `
                -Category 'Governance' `
                -Name "Lifecycle Workflow check $checkId" `
                -Status 'INFO' `
                -Detail "$skipDetail Error: $_" `
                -Recommendation 'Connect-MgGraph -Scopes "LifecycleWorkflows.Read.All". Ensure Entra ID Governance / E5 license.' `
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
            $_.Category -eq 'joiner' -or
            ($_ | ConvertTo-Json -Depth 5) -match '(?i)(OnAttributeUpdated|joiner)'
        }

        if (($joinerWorkflows | Measure-Object).Count -eq 0) {
            $status = 'MEDIUM'
            $detail = 'No joiner (onboarding) Lifecycle Workflows found. New employees may not have accounts provisioned and access configured automatically.'
        }
        else {
            $joinerNames = ($joinerWorkflows | ForEach-Object { $_.DisplayName }) -join ', '
            $status = 'PASS'
            $detail = "Joiner workflow(s) found: $joinerNames."
        }

        $results.Add((New-CheckResult `
            -CheckId 'LCW-002' `
            -Category 'Governance' `
            -Name 'Joiner workflow configured (new employee onboarding)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create a joiner Lifecycle Workflow triggered by employee start date. Include tasks: generate TAP, add to groups/teams, assign access packages, send welcome email.' `
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
        $leaverWorkflows = $workflows | Where-Object { $_.Category -eq 'leaver' }

        if (($leaverWorkflows | Measure-Object).Count -eq 0) {
            $status = 'HIGH'
            $detail = 'No leaver (offboarding) Lifecycle Workflows found. Accounts of departed employees may not be disabled automatically, creating a persistent access risk.'
        }
        else {
            $leaverNames = ($leaverWorkflows | ForEach-Object { $_.DisplayName }) -join ', '
            $status = 'PASS'
            $detail = "Leaver workflow(s) found: $leaverNames."
        }

        $results.Add((New-CheckResult `
            -CheckId 'LCW-003' `
            -Category 'Governance' `
            -Name 'Leaver workflow configured (offboarding)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create a leaver Lifecycle Workflow triggered by employee leave date. Include tasks: disable account, revoke sessions, remove group memberships, remove access packages.' `
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
                try {
                    $tasks = Get-MgIdentityGovernanceLifecycleWorkflowTask `
                        -WorkflowId $leaver.Id `
                        -All `
                        -ErrorAction Stop

                    $taskDefIds = $tasks | ForEach-Object { $_.TaskDefinitionId }

                    $hasDisableUser         = $taskDefIds -contains $disableSignInTaskDef
                    $hasRemoveAccessPackage = $taskDefIds -contains $removeAccessPackageTaskDef

                    $missingTasks = [System.Collections.Generic.List[string]]::new()
                    if (-not $hasDisableUser)         { $missingTasks.Add("disableUser ($disableSignInTaskDef)") }
                    if (-not $hasRemoveAccessPackage) { $missingTasks.Add("removeAccessPackageAssignmentForUser ($removeAccessPackageTaskDef)") }

                    if ($missingTasks.Count -gt 0) {
                        $incompleteWorkflows.Add("'$($leaver.DisplayName)' missing tasks: $($missingTasks -join ', ')")
                    }
                }
                catch {
                    $incompleteWorkflows.Add("'$($leaver.DisplayName)' — could not retrieve tasks: $_")
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
                -Recommendation 'Ensure leaver workflows include at minimum: (1) Disable user account, (2) Remove access package assignments, (3) Remove group memberships, (4) Revoke all sessions.' `
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
    # LCW-005: Workflow execution history (last 30 days)
    # Get-MgIdentityGovernanceLifecycleWorkflowRun requires module >= 2.x
    # -------------------------------------------------------------------------
    $cutoff = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $executionSummary = [System.Collections.Generic.List[string]]::new()
    $totalRuns  = 0
    $failedRuns = 0

    $runCmdAvailable = [bool](Get-Command Get-MgIdentityGovernanceLifecycleWorkflowRun -ErrorAction SilentlyContinue)

    if (-not $runCmdAvailable) {
        $results.Add((New-CheckResult `
            -CheckId 'LCW-005' `
            -Category 'Governance' `
            -Name 'Workflow execution history (last 30 days)' `
            -Status 'INFO' `
            -Detail 'Get-MgIdentityGovernanceLifecycleWorkflowRun is not available in the installed module version. Update Microsoft.Graph.Identity.Governance to >= 2.x or use the Graph variant: scripts/modules/Governance/Test-LifecycleWorkflows.ps1.' `
            -Recommendation 'Update module: Update-Module Microsoft.Graph.Identity.Governance. Then retry.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/lifecycle-workflow-history' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
        return $results
    }

    foreach ($workflow in $workflows) {
        try {
            $runs = Get-MgIdentityGovernanceLifecycleWorkflowRun `
                -WorkflowId $workflow.Id `
                -All `
                -Filter "startDateTime ge $cutoff" `
                -ErrorAction Stop

            $runCount     = ($runs | Measure-Object).Count
            $failCount    = ($runs | Where-Object { $_.Status -in @('failed', 'cancelled') } | Measure-Object).Count
            $successCount = ($runs | Where-Object { $_.Status -eq 'completed' } | Measure-Object).Count

            $totalRuns  += $runCount
            $failedRuns += $failCount

            if ($runCount -gt 0) {
                $executionSummary.Add("'$($workflow.DisplayName)' (category: $($workflow.Category)): $runCount runs | $successCount succeeded | $failCount failed")
            }
            else {
                $executionSummary.Add("'$($workflow.DisplayName)' (category: $($workflow.Category)): no runs in last 30 days")
            }
        }
        catch {
            $executionSummary.Add("'$($workflow.DisplayName)': could not retrieve runs — $_")
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

    return $results
}
