#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Entra ID diagnostic settings forwarding configuration. PS-ONLY INFO STUB.

.DESCRIPTION
    PS-ONLY VARIANT — STUB MODULE. Emits INFO findings only.

    WHY NOT AVAILABLE VIA PS-ONLY:
    Azure Monitor Diagnostic Settings require the Az.Monitor PowerShell module
    OR the Azure REST API at:
        GET /subscriptions/{id}/providers/microsoft.aad/diagnosticSettings

    There is NO Get-Mg* cmdlet in the Microsoft.Graph.* modules that covers the
    Diagnostic Settings endpoint. The Graph API itself does not expose this path.

    The equivalent cmdlet requires:
        Import-Module Az.Monitor
        Connect-AzAccount
        Get-AzDiagnosticSetting -ResourceId "/providers/microsoft.aad"

    WHAT THIS MODULE DOES:
    - Confirms audit log accessibility via Get-MgAuditLogDirectoryAudit (proxy check)
    - Detects license tier to estimate in-portal retention
    - Emits actionable INFO findings with Azure portal verification steps
    - References the Graph variant for automated checks

    SEE ALSO (Graph variant):
        scripts/modules/Monitoring/Test-DiagnosticSettings.ps1

    Required connection:
        Connect-MgGraph -Scopes "AuditLog.Read.All"

    Required scopes:
        AuditLog.Read.All

    Required modules:
        Microsoft.Graph.Authentication
        Microsoft.Graph.Reports (for audit log proxy check)

    For FULL diagnostic settings check:
        Install-Module Az.Monitor
        Connect-AzAccount
        Get-AzDiagnosticSetting -ResourceId "/providers/microsoft.aad"

    License: E3 minimum; E5 for full audit retention
    SC-300 Domain: Monitoring & Alerting

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-DiagnosticSettings {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # DST-001: Entra ID diagnostic settings — NOT AVAILABLE via PS-only
    # -------------------------------------------------------------------------
    $dst001Detail  = 'Diagnostic Settings (Azure Monitor forwarding) cannot be verified via the Microsoft.Graph.* PowerShell modules. '
    $dst001Detail += 'No Get-Mg* cmdlet covers this endpoint. '
    $dst001Detail += 'To check: (1) Install-Module Az.Monitor, (2) Connect-AzAccount, '
    $dst001Detail += "(3) Get-AzDiagnosticSetting -ResourceId '/providers/microsoft.aad'. "
    $dst001Detail += 'Alternatively, use the Graph variant: scripts/modules/Monitoring/Test-DiagnosticSettings.ps1. '
    $dst001Detail += 'Manual verification: Azure portal → Microsoft Entra ID → Monitoring → Diagnostic settings.'

    $results.Add((New-CheckResult `
        -CheckId 'DST-001' `
        -Category 'Monitoring' `
        -Name 'Entra ID Diagnostic Settings' `
        -Status 'INFO' `
        -Detail $dst001Detail `
        -Recommendation "Verify in Azure portal: Entra ID → Monitoring → Diagnostic settings. Ensure at minimum 'SignInLogs', 'AuditLogs', 'NonInteractiveUserSignInLogs', and 'RiskyUsers' are forwarded to Log Analytics or SIEM." `
        -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # DST-002: Sign-in log SIEM forwarding — NOT AVAILABLE via PS-only
    # Proxy: confirm sign-in logs are accessible at all (necessary prerequisite)
    # -------------------------------------------------------------------------
    $logsPresent = $false
    try {
        $twoHoursAgo  = (Get-Date).AddHours(-2).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $recentSignIns = Get-MgAuditLogSignIn `
            -Filter "createdDateTime ge $twoHoursAgo" `
            -Top 5 `
            -ErrorAction Stop
        $logsPresent   = ($recentSignIns | Measure-Object).Count -gt 0
    }
    catch {
        Write-Verbose "Could not check sign-in log accessibility: $_"
    }

    $dst002Detail  = if ($logsPresent) {
        "Sign-in logs are present in Entra ID (recent events found in last 2 hours). "
    } else {
        "No recent sign-in logs found via Get-MgAuditLogSignIn — logs may not be flowing or AuditLog.Read.All scope is missing. "
    }
    $dst002Detail += 'IMPORTANT: Log forwarding to SIEM/Log Analytics cannot be confirmed via PS-only tooling. '
    $dst002Detail += 'Without forwarding to Log Analytics or SIEM, logs are limited to 30-90 days retention and are not available for automated threat detection. '
    $dst002Detail += 'Use Az.Monitor cmdlet Get-AzDiagnosticSetting or verify manually in the Azure portal.'

    $results.Add((New-CheckResult `
        -CheckId 'DST-002' `
        -Category 'Monitoring' `
        -Name 'Sign-In Logs Forwarded to SIEM' `
        -Status 'HIGH' `
        -Detail $dst002Detail `
        -Recommendation "Configure diagnostic settings to forward SignInLogs and AuditLogs to Log Analytics workspace (for Microsoft Sentinel) or Event Hub (for third-party SIEM). Azure portal path: Entra ID → Monitoring → Diagnostic settings." `
        -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

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

        $dst003Detail = "$licenseNote Sign-in log retention in Entra ID portal: $retentionDays days. Audit log retention: $(if ($hasP2) { '90 days' } else { '30 days' })."
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
