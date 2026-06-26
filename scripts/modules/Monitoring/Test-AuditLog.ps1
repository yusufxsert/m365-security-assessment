#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Entra ID audit log accessibility, retention, admin activity, risky sign-ins,
    and guest invitation volume.

.DESCRIPTION
    Test-AuditLog evaluates whether directory audit logs are accessible, estimates
    retention based on license, counts recent admin operations (last 7 days), checks
    for risky sign-in events in the last 30 days, and reports guest invitation
    activity in the last 30 days.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        AuditLog.Read.All
        Directory.Read.All

    License Required: E3 minimum; extended audit retention requires E5
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/Monitoring/Test-AuditLog.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-AuditLog {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # AUD-001: Directory audit log accessible
    # -------------------------------------------------------------------------
    try {
        $dirAuditUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1&`$select=id,activityDateTime,activityDisplayName,loggedByService"
        $dirAuditResp = Invoke-MgGraphRequest -Method GET -Uri $dirAuditUri -ErrorAction Stop

        if ($dirAuditResp.value -and $dirAuditResp.value.Count -gt 0) {
            $latestEvent = $dirAuditResp.value[0]
            $aud001Status = 'PASS'
            $aud001Detail = "Directory audit log is accessible and contains events. Most recent event: '$($latestEvent.activityDisplayName)' at $($latestEvent.activityDateTime) (service: $($latestEvent.loggedByService))."
        }
        else {
            $aud001Status = 'CRITICAL'
            $aud001Detail = 'Directory audit log query returned no events. Audit logging may be disabled or the service principal lacks AuditLog.Read.All permission.'
        }
    }
    catch {
        $aud001Status = 'CRITICAL'
        $aud001Detail = "Directory audit log is not accessible. Required: AuditLog.Read.All. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'AUD-001' `
        -Category 'Monitoring' `
        -Name 'Directory Audit Log Accessible' `
        -Status $aud001Status `
        -Detail $aud001Detail `
        -Recommendation 'Ensure audit logging is enabled. Verify AuditLog.Read.All is granted. If no events exist, confirm admin activities have occurred and the audit log is not disabled in the Purview compliance portal.' `
        -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    if ($aud001Status -eq 'CRITICAL') {
        return $results  # Cannot run further audit checks without log access
    }

    # -------------------------------------------------------------------------
    # AUD-002: Audit log retention period (license-based)
    # -------------------------------------------------------------------------
    try {
        $skusResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus' `
            -ErrorAction Stop
        $skus = $skusResp.value

        $hasE5 = $skus | Where-Object {
            $_.skuPartNumber -match 'ENTERPRISEPREMIUM|SPE_E5|M365EDU_A5' -and
            $_.capabilityStatus -eq 'Enabled'
        }
        $hasAuditPremium = $skus | Where-Object {
            $_.skuPartNumber -match 'PURVIEW_AUDIT|COMPLIANCE_P2|M365_AUDIT' -and
            $_.capabilityStatus -eq 'Enabled'
        }

        if ($hasAuditPremium) {
            $aud002Status = 'PASS'
            $aud002Detail = 'Microsoft Purview Audit Premium detected. Extended retention up to 10 years for critical events.'
        }
        elseif ($hasE5) {
            $aud002Status = 'PASS'
            $aud002Detail = 'E5 license detected. Audit log retention is 1 year by default. Consider Audit Premium for 10-year retention of critical events.'
        }
        else {
            $aud002Status = 'HIGH'
            $aud002Detail = 'E3 license detected. Default audit log retention is 90 days. Without log forwarding or E5, events older than 90 days are lost.'
        }
    }
    catch {
        $aud002Status = 'INFO'
        $aud002Detail = "License check failed — retention period could not be determined. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'AUD-002' `
        -Category 'Monitoring' `
        -Name 'Audit Log Retention Period' `
        -Status $aud002Status `
        -Detail $aud002Detail `
        -Recommendation 'Upgrade to E5 for 1-year retention or configure diagnostic settings to forward logs to a Log Analytics workspace / SIEM for extended archival. 90-day retention is insufficient for most incident investigations.' `
        -Reference 'https://learn.microsoft.com/purview/audit-log-retention-policies' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # AUD-003: Admin activity audit (recent 7 days count)
    # -------------------------------------------------------------------------
    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $adminActivityUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=loggedByService eq 'Core Directory' and activityDateTime ge $sevenDaysAgo&`$select=id,activityDisplayName,initiatedBy,activityDateTime&`$top=100"
        $adminActivityResp = Invoke-MgGraphRequest -Method GET -Uri $adminActivityUri -ErrorAction Stop

        $adminEvents = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $adminActivityResp.value) { $adminEvents.Add($e) }
        $nextLink = $adminActivityResp.'@odata.nextLink'
        # Cap at 500 events for performance
        while ($nextLink -and $adminEvents.Count -lt 500) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($e in $page.value) { $adminEvents.Add($e) }
            $nextLink = $page.'@odata.nextLink'
        }

        $topActivities = $adminEvents | Group-Object activityDisplayName | Sort-Object Count -Descending |
                         Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }

        $results.Add((New-CheckResult `
            -CheckId 'AUD-003' `
            -Category 'Monitoring' `
            -Name 'Admin Activity in Last 7 Days' `
            -Status 'INFO' `
            -Detail "Core Directory admin operations in last 7 days: $($adminEvents.Count). Top activities: $($topActivities -join '; ')." `
            -Recommendation 'Review admin activity regularly. Unusual spikes in role assignments, policy changes, or user modifications may indicate unauthorized activity.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'AUD-003' `
            -Category 'Monitoring' `
            -Name 'Admin Activity in Last 7 Days' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: AuditLog.Read.All. Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AUD-004: Risky sign-in events in last 30 days
    # -------------------------------------------------------------------------
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $riskyUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=riskLevelAggregated ne 'none' and createdDateTime ge $thirtyDaysAgo&`$select=userPrincipalName,riskLevelAggregated,riskState,createdDateTime&`$top=100"
        $riskyResp = Invoke-MgGraphRequest -Method GET -Uri $riskyUri -ErrorAction Stop

        $riskySignIns = [System.Collections.Generic.List[object]]::new()
        foreach ($s in $riskyResp.value) { $riskySignIns.Add($s) }
        $nextLink = $riskyResp.'@odata.nextLink'
        while ($nextLink -and $riskySignIns.Count -lt 200) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($s in $page.value) { $riskySignIns.Add($s) }
            $nextLink = $page.'@odata.nextLink'
        }

        $highRisk    = @($riskySignIns | Where-Object { $_.riskLevelAggregated -eq 'high' })
        $mediumRisk  = @($riskySignIns | Where-Object { $_.riskLevelAggregated -eq 'medium' })
        $unremediated = @($riskySignIns | Where-Object { $_.riskState -notin @('remediated', 'dismissed', 'confirmedSafe') })

        $uniqueRiskyUsers = ($riskySignIns | Select-Object -ExpandProperty userPrincipalName | Sort-Object -Unique).Count

        if ($riskySignIns.Count -gt 50) {
            $aud004Status = 'HIGH'
        }
        elseif ($riskySignIns.Count -gt 10) {
            $aud004Status = 'MEDIUM'
        }
        elseif ($riskySignIns.Count -gt 0) {
            $aud004Status = 'LOW'
        }
        else {
            $aud004Status = 'PASS'
        }

        $aud004Detail = "Risky sign-in events (last 30 days): $($riskySignIns.Count) total across $uniqueRiskyUsers user(s). High risk: $($highRisk.Count), Medium risk: $($mediumRisk.Count). Unremediated: $($unremediated.Count)."
        if ($riskySignIns.Count -eq 0) {
            $aud004Detail = 'No risky sign-in events found in the last 30 days. Note: risk data requires Entra ID P2 license.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'AUD-004' `
            -Category 'Monitoring' `
            -Name 'Risky Sign-In Events (Last 30 Days)' `
            -Status $aud004Status `
            -Detail $aud004Detail `
            -Recommendation 'Investigate unremediated risky sign-ins in Entra ID Protection. Configure risk-based Conditional Access to auto-require MFA or block high-risk sign-ins. Ensure Identity Protection is licensed (P2).' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
            -AffectedObjects @($unremediated | Select-Object -First 20 | ForEach-Object { $_.userPrincipalName })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'AUD-004' `
            -Category 'Monitoring' `
            -Name 'Risky Sign-In Events (Last 30 Days)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or Entra ID P2 not licensed. Required: AuditLog.Read.All, IdentityRiskyUser.Read.All. Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All. Risk data requires Entra ID P2 / E5 license.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AUD-005: Guest invitations in last 30 days
    # -------------------------------------------------------------------------
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $guestInviteUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Invite external user' and activityDateTime ge $thirtyDaysAgo&`$select=id,activityDateTime,initiatedBy,targetResources&`$top=100"
        $guestInviteResp = Invoke-MgGraphRequest -Method GET -Uri $guestInviteUri -ErrorAction Stop

        $guestInvites = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $guestInviteResp.value) { $guestInvites.Add($e) }
        $nextLink = $guestInviteResp.'@odata.nextLink'
        while ($nextLink -and $guestInvites.Count -lt 200) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($e in $page.value) { $guestInvites.Add($e) }
            $nextLink = $page.'@odata.nextLink'
        }

        # Count invitations per initiator
        $inviterCounts = $guestInvites | ForEach-Object {
            $initiator = $_.initiatedBy.user.userPrincipalName ?? $_.initiatedBy.app.displayName ?? 'Unknown'
            $initiator
        } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5

        $topInviters = $inviterCounts | ForEach-Object { "$($_.Name): $($_.Count)" }

        $results.Add((New-CheckResult `
            -CheckId 'AUD-005' `
            -Category 'Monitoring' `
            -Name 'Guest Invitations (Last 30 Days)' `
            -Status 'INFO' `
            -Detail "Guest invitations in last 30 days: $($guestInvites.Count). Top inviters: $($topInviters -join '; ')." `
            -Recommendation 'Review guest invitation volume and top inviters. Unexpected spikes may indicate compromised accounts sending invitations or misconfigured external collaboration settings. Restrict invitations to specific users or groups via External Collaboration Settings.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @($topInviters)))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'AUD-005' `
            -Category 'Monitoring' `
            -Name 'Guest Invitations (Last 30 Days)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: AuditLog.Read.All. Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
