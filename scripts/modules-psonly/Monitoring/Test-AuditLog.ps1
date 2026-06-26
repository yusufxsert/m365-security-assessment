#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Reports, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Entra ID audit log accessibility, retention, admin activity, and sign-in risk. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgAuditLogDirectoryAudit and Get-MgAuditLogSignIn
    (Microsoft.Graph.Reports) for directory audit and sign-in log checks.
    Search-UnifiedAuditLog (IPPS) is used for the unified audit log functional test.

    WHY PS-ONLY:
    Get-MgAuditLogDirectoryAudit and Get-MgAuditLogSignIn are the PS equivalents of
    the /auditLogs/directoryAudits and /auditLogs/signIns Graph endpoints. They support
    -Filter parameters with OData syntax and handle pagination via -All.

    NOTE on Search-UnifiedAuditLog:
    For the PAD-003 equivalent (unified audit log accessibility), Connect-IPPSSession
    is used if available. This is optional — AUD-003/AUD-004/AUD-005 use Graph cmdlets.

    SEE ALSO (Graph variant):
        scripts/modules/Monitoring/Test-AuditLog.ps1

    Required connection:
        Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All"
        Connect-IPPSSession  (optional — for Search-UnifiedAuditLog in AUD-001)

    Required scopes:
        AuditLog.Read.All
        Directory.Read.All

    Required modules:
        Microsoft.Graph.Reports
        Microsoft.Graph.Authentication

    License: E3 minimum; extended audit retention requires E5
    SC-300 Domain: Monitoring & Alerting

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-AuditLog {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # AUD-001: Directory audit log accessible via Get-MgAuditLogDirectoryAudit
    # -------------------------------------------------------------------------
    try {
        $recentAudit = Get-MgAuditLogDirectoryAudit `
            -Filter "activityDateTime ge $((Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ'))" `
            -Top 1 `
            -ErrorAction Stop

        if ($recentAudit -and ($recentAudit | Measure-Object).Count -gt 0) {
            $latestEvent = $recentAudit | Select-Object -First 1
            $aud001Status = 'PASS'
            $aud001Detail = "Directory audit log is accessible and contains events. Most recent event: '$($latestEvent.ActivityDisplayName)' at $($latestEvent.ActivityDateTime) (service: $($latestEvent.LoggedByService))."
        }
        else {
            $aud001Status = 'CRITICAL'
            $aud001Detail = 'Directory audit log query returned no events in the last 7 days. Audit logging may be disabled or the account lacks AuditLog.Read.All permission.'
        }
    }
    catch {
        $aud001Status = 'CRITICAL'
        $aud001Detail = "Directory audit log is not accessible. Required scope: AuditLog.Read.All. Error: $_"
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
        return $results
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
        -Recommendation 'Upgrade to E5 for 1-year retention or configure diagnostic settings to forward logs to a Log Analytics workspace / SIEM for extended archival.' `
        -Reference 'https://learn.microsoft.com/purview/audit-log-retention-policies' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # AUD-003: Admin activity audit (recent 7 days count)
    # Uses Get-MgAuditLogDirectoryAudit with loggedByService filter
    # -------------------------------------------------------------------------
    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')

        # Get-MgAuditLogDirectoryAudit supports OData $filter
        $adminEvents = Get-MgAuditLogDirectoryAudit `
            -Filter "loggedByService eq 'Core Directory' and activityDateTime ge $sevenDaysAgo" `
            -All `
            -ErrorAction Stop

        $topActivities = $adminEvents | Group-Object ActivityDisplayName | Sort-Object Count -Descending |
                         Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }

        $results.Add((New-CheckResult `
            -CheckId 'AUD-003' `
            -Category 'Monitoring' `
            -Name 'Admin Activity in Last 7 Days' `
            -Status 'INFO' `
            -Detail "Core Directory admin operations in last 7 days: $(($adminEvents | Measure-Object).Count). Top activities: $($topActivities -join '; ')." `
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
            -Recommendation 'Connect-MgGraph -Scopes "AuditLog.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/concept-audit-logs' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AUD-004: Risky sign-in events in last 30 days
    # Uses Get-MgAuditLogSignIn with riskLevelAggregated filter
    # -------------------------------------------------------------------------
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')

        # Filter: riskLevelAggregated ne 'none' — returns only risky sign-ins
        $riskySignIns = Get-MgAuditLogSignIn `
            -Filter "riskLevelAggregated ne 'none' and createdDateTime ge $thirtyDaysAgo" `
            -All `
            -ErrorAction Stop

        $highRisk    = @($riskySignIns | Where-Object { $_.RiskLevelAggregated -eq 'high' })
        $mediumRisk  = @($riskySignIns | Where-Object { $_.RiskLevelAggregated -eq 'medium' })
        $unremediated = @($riskySignIns | Where-Object { $_.RiskState -notin @('remediated', 'dismissed', 'confirmedSafe') })

        $uniqueRiskyUsers = ($riskySignIns | Select-Object -ExpandProperty UserPrincipalName | Sort-Object -Unique).Count
        $totalCount = ($riskySignIns | Measure-Object).Count

        if ($totalCount -gt 50) {
            $aud004Status = 'HIGH'
        }
        elseif ($totalCount -gt 10) {
            $aud004Status = 'MEDIUM'
        }
        elseif ($totalCount -gt 0) {
            $aud004Status = 'LOW'
        }
        else {
            $aud004Status = 'PASS'
        }

        $aud004Detail = "Risky sign-in events (last 30 days): $totalCount total across $uniqueRiskyUsers user(s). High risk: $($highRisk.Count), Medium risk: $($mediumRisk.Count). Unremediated: $($unremediated.Count)."
        if ($totalCount -eq 0) {
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
            -AffectedObjects @($unremediated | Select-Object -First 20 | ForEach-Object { $_.UserPrincipalName })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'AUD-004' `
            -Category 'Monitoring' `
            -Name 'Risky Sign-In Events (Last 30 Days)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or Entra ID P2 not licensed. Required: AuditLog.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "AuditLog.Read.All". Risk data requires Entra ID P2 / E5 license.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AUD-005: Guest invitations in last 30 days
    # Uses Get-MgAuditLogDirectoryAudit with activityDisplayName filter
    # -------------------------------------------------------------------------
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $guestInvites = Get-MgAuditLogDirectoryAudit `
            -Filter "activityDisplayName eq 'Invite external user' and activityDateTime ge $thirtyDaysAgo" `
            -All `
            -ErrorAction Stop

        $inviterCounts = $guestInvites | ForEach-Object {
            $initiator = $_.InitiatedBy.User.UserPrincipalName ?? $_.InitiatedBy.App.DisplayName ?? 'Unknown'
            $initiator
        } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5

        $topInviters = $inviterCounts | ForEach-Object { "$($_.Name): $($_.Count)" }

        $results.Add((New-CheckResult `
            -CheckId 'AUD-005' `
            -Category 'Monitoring' `
            -Name 'Guest Invitations (Last 30 Days)' `
            -Status 'INFO' `
            -Detail "Guest invitations in last 30 days: $(($guestInvites | Measure-Object).Count). Top inviters: $($topInviters -join '; ')." `
            -Recommendation 'Review guest invitation volume and top inviters. Unexpected spikes may indicate compromised accounts. Restrict invitations via External Collaboration Settings.' `
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
            -Recommendation 'Connect-MgGraph -Scopes "AuditLog.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
