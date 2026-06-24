#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits SIEM integration indicators: Sentinel/security alerts, Entra SIEM
    diagnostic guidance, and Continuous Access Evaluation status.

.DESCRIPTION
    Test-SIEMIntegration evaluates security alert volume via the Graph Security
    Alerts API (as a proxy for SIEM connector activity), provides prescriptive
    guidance on Sentinel Entra ID connector verification, and checks whether
    Continuous Access Evaluation (CAE) is enabled in the tenant.

    Direct verification of Sentinel workspace connectivity or Azure Monitor
    diagnostic settings requires Azure subscription-level access and cannot
    be performed via the Graph API alone. This module surfaces what is knowable
    and provides actionable portal verification steps.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        SecurityEvents.Read.All

    License Required:
        SIM-001 through SIM-003: INFO only (requires Azure portal verification)
        SIM-004 CAE: E3 minimum

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
#>

function Test-SIEMIntegration {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # SIM-001: Microsoft Sentinel connected to Entra ID
    # -------------------------------------------------------------------------
    # Graph cannot enumerate Sentinel workspace connections or data connectors.
    # We check for diagnostic settings indirectly via sign-in log availability
    # and provide portal verification guidance.

    try {
        $signInTestUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1&`$select=id,createdDateTime"
        $signInTestResp = Invoke-MgGraphRequest -Method GET -Uri $signInTestUri -ErrorAction Stop
        $logsPresent = $signInTestResp.value -and $signInTestResp.value.Count -gt 0

        $sim001Detail  = if ($logsPresent) { "Sign-in logs are present in Entra ID (required for Sentinel ingestion). " } else { "No sign-in logs found — logs may not be enabled. " }
        $sim001Detail += "IMPORTANT: Sentinel connector status cannot be verified via Graph API. "
        $sim001Detail += "Verification steps: (1) Azure portal → Microsoft Sentinel → Data connectors → 'Microsoft Entra ID'. "
        $sim001Detail += "(2) Confirm status = 'Connected'. (3) Verify tables AzureADSignInLogs and AuditLogs in Log Analytics."
    }
    catch {
        $sim001Detail = "Sign-in log test failed (AuditLog.Read.All required). Sentinel connector status must be verified manually in the Azure portal. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'SIM-001' `
        -Category 'Monitoring' `
        -Name 'Microsoft Sentinel Connected to Entra ID' `
        -Status 'INFO' `
        -Detail $sim001Detail `
        -Recommendation "Enable the Microsoft Entra ID data connector in Sentinel. Select all log types: SignInLogs, AuditLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs, ManagedIdentitySignInLogs, ProvisioningLogs, RiskyUsers, UserRiskEvents. This is a free connector — no additional cost for log ingestion." `
        -Reference 'https://learn.microsoft.com/azure/sentinel/connect-azure-active-directory' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SIM-002: Security API alert connectors (recent alert volume)
    # -------------------------------------------------------------------------
    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $alertsUri = "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=createdDateTime ge $sevenDaysAgo&`$select=id,title,severity,status,createdDateTime,detectionSource&`$top=100"
        $alertsResp = Invoke-MgGraphRequest -Method GET -Uri $alertsUri -ErrorAction Stop

        $alerts = [System.Collections.Generic.List[object]]::new()
        foreach ($a in $alertsResp.value) { $alerts.Add($a) }
        $nextLink = $alertsResp.'@odata.nextLink'
        while ($nextLink -and $alerts.Count -lt 200) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($a in $page.value) { $alerts.Add($a) }
            $nextLink = $page.'@odata.nextLink'
        }

        $highAlerts    = @($alerts | Where-Object { $_.severity -eq 'high' })
        $mediumAlerts  = @($alerts | Where-Object { $_.severity -eq 'medium' })
        $openAlerts    = @($alerts | Where-Object { $_.status -notin @('resolved', 'inProgress') })

        $bySource = $alerts | Group-Object detectionSource | Sort-Object Count -Descending |
                    Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }

        $sim002Detail = "Security alerts in last 7 days: $($alerts.Count) total. High: $($highAlerts.Count), Medium: $($mediumAlerts.Count). Open/unresolved: $($openAlerts.Count). Sources: $($bySource -join ', ')."

        if ($alerts.Count -eq 0) {
            $sim002Detail = 'No security alerts found in last 7 days via Graph Security API. This may indicate no detections, no connected security products, or the API requires E5 licensing.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'SIM-002' `
            -Category 'Monitoring' `
            -Name 'Security API Alert Connectors' `
            -Status 'INFO' `
            -Detail $sim002Detail `
            -Recommendation 'If alert count is zero with E5 licensing, verify security product connections in the Microsoft 365 Defender portal. Unresolved high-severity alerts require immediate investigation.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/investigate-alerts' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
            -AffectedObjects @($highAlerts | Select-Object -First 10 | ForEach-Object { "$($_.title) [$($_.severity)]" })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'SIM-002' `
            -Category 'Monitoring' `
            -Name 'Security API Alert Connectors' `
            -Status 'INFO' `
            -Detail "Alert API not accessible. Required: SecurityEvents.Read.All. Error: $_" `
            -Recommendation 'Grant SecurityEvents.Read.All to the service principal. Security alerts require E5 or Defender for Endpoint P2 licensing.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/investigate-alerts' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SIM-003: Entra SIEM integration via Diagnostic Settings (guidance)
    # -------------------------------------------------------------------------
    $sim003Detail  = 'Entra ID SIEM integration via diagnostic settings cannot be verified through the Graph API — Azure subscription-level permissions are required. '
    $sim003Detail += 'Required verification steps: '
    $sim003Detail += '(1) Azure portal → Microsoft Entra ID → Monitoring → Diagnostic settings. '
    $sim003Detail += "(2) Verify a setting exists that forwards to Log Analytics workspace (Sentinel) or Event Hub (third-party SIEM). "
    $sim003Detail += "(3) Required log categories: SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs, AuditLogs, RiskyUsers, UserRiskEvents, ManagedIdentitySignInLogs. "
    $sim003Detail += "(4) In Sentinel: navigate to Data connectors → Microsoft Entra ID → confirm 'Connected' status."

    $results.Add((New-CheckResult `
        -CheckId 'SIM-003' `
        -Category 'Monitoring' `
        -Name 'Entra SIEM Integration via Diagnostic Settings' `
        -Status 'INFO' `
        -Detail $sim003Detail `
        -Recommendation 'Validate Entra ID diagnostic settings in the Azure portal. If not configured, create a diagnostic setting forwarding all identity log categories to your Log Analytics workspace. This is a prerequisite for Sentinel Entra ID detection rules.' `
        -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SIM-004: Continuous Access Evaluation (CAE) enabled
    # -------------------------------------------------------------------------
    try {
        # CAE policy is in beta endpoint
        $caeUri = 'https://graph.microsoft.com/beta/policies/continuousAccessEvaluationPolicy'
        $caeResp = Invoke-MgGraphRequest -Method GET -Uri $caeUri -ErrorAction Stop

        $caeIsEnabled   = $caeResp.isEnabled
        $caeMigrationState = $caeResp.migrate  # strict mode
        $caeDescription = $caeResp.description

        if (-not $caeIsEnabled) {
            $sim004Status = 'MEDIUM'
            $sim004Detail = 'Continuous Access Evaluation (CAE) is disabled. Sessions may remain valid for up to 1 hour after account compromise, MFA requirement changes, or device compliance changes.'
        }
        elseif ($caeMigrationState -eq $false -or $caeMigrationState -eq 'disabled') {
            $sim004Status = 'LOW'
            $sim004Detail = 'CAE is enabled but not in strict mode. In strict mode, session token lifetime is capped at 1 hour; in standard mode it is up to 1 day for some clients.'
        }
        else {
            $sim004Status = 'PASS'
            $sim004Detail = "CAE is enabled. Mode: $( if ($caeMigrationState) { 'strict (recommended)' } else { 'standard' })."
        }
    }
    catch {
        # Fallback for tenants where beta endpoint is unavailable
        $sim004Status = 'MEDIUM'
        $sim004Detail = "CAE status could not be retrieved via beta endpoint. Error: $_. Verify in Entra portal: Identity → Protection → Continuous access evaluation."
    }

    $results.Add((New-CheckResult `
        -CheckId 'SIM-004' `
        -Category 'Monitoring' `
        -Name 'Continuous Access Evaluation (CAE) Enabled' `
        -Status $sim004Status `
        -Detail $sim004Detail `
        -Recommendation "Enable CAE in strict mode (Entra ID → Protection → Continuous access evaluation → Strict enforcement). CAE causes instant revocation of session tokens when user risk, location, or compliance changes — a critical control for real-time threat response." `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation' `
        -CISControl '' -SC300Domain 'Authentication & Access Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
