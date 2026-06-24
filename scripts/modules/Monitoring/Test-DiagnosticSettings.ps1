#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Entra ID diagnostic settings: sign-in log forwarding and retention.

.DESCRIPTION
    Test-DiagnosticSettings checks whether Entra ID diagnostic settings are
    configured to forward sign-in and audit logs to an external destination
    (Log Analytics, Event Hub, or Storage Account). It also reports expected
    log retention based on the tenant license and provides guidance on verifying
    full diagnostic settings in the Azure portal.

    Full diagnostic settings configuration requires Azure subscription-level
    permissions (Reader or Monitoring Contributor) which are outside the scope
    of a Graph-only assessment. This module surfaces what is knowable via Graph
    and provides actionable guidance for the remainder.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        AuditLog.Read.All

    License Required: E3 minimum; E5 for full audit retention
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
#>

function Test-DiagnosticSettings {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # DST-001: Entra ID diagnostic settings (Azure Monitor forwarding)
    # -------------------------------------------------------------------------
    # Graph does not expose Azure Monitor diagnostic settings directly.
    # We test reachability via the beta audit endpoint and provide guidance.
    try {
        $betaAuditUri = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$top=1&`$select=id"
        $null = Invoke-MgGraphRequest -Method GET -Uri $betaAuditUri -ErrorAction Stop

        # Try to detect custom security attribute audits as proxy for advanced logging config
        try {
            $customAttrUri = "https://graph.microsoft.com/beta/auditLogs/customSecurityAttributeAudits?`$top=1&`$select=id"
            $customAttrResp = Invoke-MgGraphRequest -Method GET -Uri $customAttrUri -ErrorAction Stop
            $customAttrAvailable = $true
        }
        catch {
            $customAttrAvailable = $false
        }

        $dst001Status = 'INFO'
        $dst001Detail = "Entra ID audit logs are accessible via Graph API. Custom security attribute audit logs: $( if ($customAttrAvailable) { 'accessible' } else { 'not accessible (requires AttributeLog.Read.All)' })."
        $dst001Detail += ' NOTE: Full diagnostic settings (forwarding to Log Analytics/Event Hub/Storage) can only be verified in the Azure portal under: Entra ID → Monitoring → Diagnostic settings. This check cannot verify forwarding status via Graph API alone.'
    }
    catch {
        $dst001Status = 'INFO'
        $dst001Detail = "Could not verify Entra ID audit log accessibility via beta endpoint. Error: $_. Diagnostic settings verification requires Azure portal access."
    }

    $results.Add((New-CheckResult `
        -CheckId 'DST-001' `
        -Category 'Monitoring' `
        -Name 'Entra ID Diagnostic Settings' `
        -Status $dst001Status `
        -Detail $dst001Detail `
        -Recommendation "Verify in Azure portal: Entra ID → Monitoring → Diagnostic settings. Ensure at minimum 'SignInLogs', 'AuditLogs', 'NonInteractiveUserSignInLogs', and 'RiskyUsers' are forwarded to Log Analytics or SIEM." `
        -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # DST-002: Sign-in logs being forwarded to SIEM
    # -------------------------------------------------------------------------
    # Graph cannot directly enumerate Azure Monitor diagnostic settings.
    # We estimate based on log freshness and volume as a proxy indicator.
    try {
        $twoHoursAgo = (Get-Date).AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $recentSignInsUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $twoHoursAgo&`$select=id,createdDateTime&`$top=5"
        $recentSignInsResp = Invoke-MgGraphRequest -Method GET -Uri $recentSignInsUri -ErrorAction Stop
        $recentSignIns = $recentSignInsResp.value

        $dst002Status = 'HIGH'
        $dst002Detail = "Sign-in logs are present in Entra ID (recent events found: $($recentSignIns.Count) in last 2 hours). However, log forwarding to a SIEM cannot be confirmed via Graph API."
        $dst002Detail += ' Without forwarding to Log Analytics or SIEM, logs are limited to 30 days (E3) or 90 days (E5) retention and are not available for automated threat detection.'

        $results.Add((New-CheckResult `
            -CheckId 'DST-002' `
            -Category 'Monitoring' `
            -Name 'Sign-In Logs Forwarded to SIEM' `
            -Status $dst002Status `
            -Detail $dst002Detail `
            -Recommendation "Configure diagnostic settings to forward SignInLogs and AuditLogs to Log Analytics workspace (for Microsoft Sentinel) or Event Hub (for third-party SIEM). This is a critical control for extended retention and automated detection. Azure portal path: Entra ID → Monitoring → Diagnostic settings." `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DST-002' `
            -Category 'Monitoring' `
            -Name 'Sign-In Logs Forwarded to SIEM' `
            -Status 'HIGH' `
            -Detail "Sign-in logs not accessible. Required: AuditLog.Read.All. Cannot verify SIEM forwarding. Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All. Verify sign-in log forwarding in the Azure portal under Entra ID Diagnostic Settings.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DST-003: Entra ID sign-in log retention based on license
    # -------------------------------------------------------------------------
    try {
        $skusResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus' `
            -ErrorAction Stop
        $skus = $skusResp.value

        $hasP2 = $skus | Where-Object {
            $_.skuPartNumber -match 'AAD_PREMIUM_P2|ENTERPRISEPREMIUM|SPE_E5|M365EDU_A5' -and
            $_.capabilityStatus -eq 'Enabled'
        }
        $hasP1 = $skus | Where-Object {
            $_.skuPartNumber -match 'AAD_PREMIUM|EMS|EMSPLUSMS' -and
            $_.capabilityStatus -eq 'Enabled'
        }

        if ($hasP2) {
            $retentionDays = 90
            $licenseNote   = 'Entra ID P2 (E5) detected.'
        }
        elseif ($hasP1) {
            $retentionDays = 30
            $licenseNote   = 'Entra ID P1 (E3) detected.'
        }
        else {
            $retentionDays = 7
            $licenseNote   = 'No Entra ID P1/P2 license detected. Free tier: 7-day sign-in log retention.'
        }

        $dst003Detail = "$licenseNote Sign-in log retention in Entra ID portal: $retentionDays days. Audit log retention: $( if ($hasP2) { '90 days' } else { '30 days' })."
        if ($retentionDays -lt 90) {
            $dst003Detail += ' Forward logs to Log Analytics / SIEM to extend retention for compliance and investigation requirements.'
        }
    }
    catch {
        $dst003Detail = "License check failed — sign-in log retention period could not be determined. Default assumption: 30 days (P1) or 7 days (no license). Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'DST-003' `
        -Category 'Monitoring' `
        -Name 'Entra ID Sign-In Log Retention' `
        -Status 'INFO' `
        -Detail $dst003Detail `
        -Recommendation 'Forward sign-in logs to a Log Analytics workspace to achieve 90+ day retention and enable Sentinel detection rules. The Entra ID connector for Sentinel is free for the log forwarding itself.' `
        -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/reference-reports-data-retention' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
