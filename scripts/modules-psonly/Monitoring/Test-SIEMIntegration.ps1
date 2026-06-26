#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits SIEM integration indicators for Microsoft Sentinel and Entra ID. PS-ONLY INFO STUB.

.DESCRIPTION
    PS-ONLY VARIANT — STUB MODULE for SIM-001, SIM-002, SIM-003.
    SIM-004 (CAE) is fully implemented using Get-MgPolicyContinuousAccessEvaluationPolicy.

    WHY NOT AVAILABLE VIA PS-ONLY (SIM-001 through SIM-003):
    SIEM integration checks require:
    - Azure Monitor Diagnostic Settings (Az.Monitor module, not in Graph PS modules)
    - Microsoft Sentinel workspace connectivity (Az.SecurityInsights module)
    - Azure Security Alerts from the security/alerts_v2 endpoint (requires
      SecurityEvents.Read.All but the Invoke-MgGraphRequest call still works —
      however no dedicated Get-Mg* cmdlet for alerts_v2 exists in the public module)

    For SIM-002 (alert volume), Invoke-MgGraphRequest is used as a fallback since
    no Get-MgSecurityAlert_v2 cmdlet exists in the shipped module versions.

    WHAT THIS MODULE DOES:
    - SIM-001: INFO — Sentinel connectivity cannot be verified via PS-only
    - SIM-002: Retrieves security alert count via Invoke-MgGraphRequest (alerts_v2)
    - SIM-003: INFO — Diagnostic settings require Az.Monitor module
    - SIM-004: FULL CHECK via Get-MgPolicyContinuousAccessEvaluationPolicy

    SEE ALSO (Graph variant):
        scripts/modules/Monitoring/Test-SIEMIntegration.ps1

    Required connection:
        Connect-MgGraph -Scopes "SecurityEvents.Read.All","Policy.Read.All"

    Required scopes:
        SecurityEvents.Read.All  (for SIM-002 alerts)
        Policy.Read.All           (for SIM-004 CAE)

    Required modules:
        Microsoft.Graph.Authentication

    License: E5 for full alert/SIEM checks; E3 for CAE
    SC-300 Domain: Monitoring & Alerting

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-SIEMIntegration {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # SIM-001: Microsoft Sentinel connected to Entra ID — INFO STUB
    # Sentinel connector status is not available via Get-Mg* cmdlets.
    # -------------------------------------------------------------------------
    # Proxy test: confirm sign-in logs are accessible (required for Sentinel ingestion)
    $logsPresent = $false
    try {
        $signInTest = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=1&$select=id,createdDateTime' `
            -ErrorAction Stop
        $logsPresent = $signInTest.value -and $signInTest.value.Count -gt 0
    }
    catch {
        Write-Verbose "Sign-in log proxy test failed: $_"
    }

    $sim001Detail  = if ($logsPresent) { "Sign-in logs are present in Entra ID (required for Sentinel ingestion). " } else { "No sign-in logs found — logs may not be enabled. " }
    $sim001Detail += "IMPORTANT: Sentinel connector status cannot be verified via PS-only tooling. "
    $sim001Detail += "This check requires the Azure portal or Az.SecurityInsights module. "
    $sim001Detail += "Verification steps: (1) Azure portal → Microsoft Sentinel → Data connectors → 'Microsoft Entra ID'. "
    $sim001Detail += "(2) Confirm status = 'Connected'. (3) Verify tables AzureADSignInLogs and AuditLogs in Log Analytics. "
    $sim001Detail += "For automated checks, use the Graph variant: scripts/modules/Monitoring/Test-SIEMIntegration.ps1."

    $results.Add((New-CheckResult `
        -CheckId 'SIM-001' `
        -Category 'Monitoring' `
        -Name 'Microsoft Sentinel Connected to Entra ID' `
        -Status 'INFO' `
        -Detail $sim001Detail `
        -Recommendation "Enable the Microsoft Entra ID data connector in Sentinel. Select all log types: SignInLogs, AuditLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs, ManagedIdentitySignInLogs, ProvisioningLogs, RiskyUsers, UserRiskEvents. This is a free connector." `
        -Reference 'https://learn.microsoft.com/azure/sentinel/connect-azure-active-directory' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SIM-002: Security API alert connectors (recent alert volume)
    # No Get-Mg* for alerts_v2 — use Invoke-MgGraphRequest fallback
    # -------------------------------------------------------------------------
    try {
        $sevenDaysAgo = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $alertsResp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=createdDateTime ge $sevenDaysAgo&`$select=id,title,severity,status,createdDateTime,detectionSource&`$top=100" `
            -ErrorAction Stop

        $alerts = [System.Collections.Generic.List[object]]::new()
        foreach ($a in $alertsResp.value) { $alerts.Add($a) }
        $nextLink = $alertsResp.'@odata.nextLink'
        while ($nextLink -and $alerts.Count -lt 200) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($a in $page.value) { $alerts.Add($a) }
            $nextLink = $page.'@odata.nextLink'
        }

        $highAlerts   = @($alerts | Where-Object { $_.severity -eq 'high' })
        $mediumAlerts = @($alerts | Where-Object { $_.severity -eq 'medium' })
        $openAlerts   = @($alerts | Where-Object { $_.status -notin @('resolved', 'inProgress') })

        $bySource = $alerts | Group-Object detectionSource | Sort-Object Count -Descending |
                    Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }

        $sim002Detail = "Security alerts in last 7 days: $($alerts.Count) total. High: $($highAlerts.Count), Medium: $($mediumAlerts.Count). Open/unresolved: $($openAlerts.Count). Sources: $($bySource -join ', ')."

        if ($alerts.Count -eq 0) {
            $sim002Detail = 'No security alerts found in last 7 days via Graph Security API. This may indicate no detections, no connected security products, or E5 licensing is not present.'
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
            -Recommendation 'Connect-MgGraph -Scopes "SecurityEvents.Read.All". Security alerts require E5 or Defender for Endpoint P2 licensing.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/investigate-alerts' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SIM-003: Entra SIEM integration via Diagnostic Settings — INFO STUB
    # Requires Az.Monitor module — not available in Microsoft.Graph.* modules
    # -------------------------------------------------------------------------
    $sim003Detail  = 'Entra ID SIEM integration via diagnostic settings cannot be verified through the Microsoft.Graph.* PowerShell modules. '
    $sim003Detail += 'Azure subscription-level permissions and the Az.Monitor module are required. '
    $sim003Detail += 'Required verification steps: '
    $sim003Detail += '(1) Install-Module Az.Monitor. '
    $sim003Detail += '(2) Connect-AzAccount. '
    $sim003Detail += "(3) Get-AzDiagnosticSetting -ResourceId '/providers/microsoft.aad'. "
    $sim003Detail += "(4) Verify categories include: SignInLogs, NonInteractiveUserSignInLogs, ServicePrincipalSignInLogs, AuditLogs, RiskyUsers, UserRiskEvents. "
    $sim003Detail += "(5) In Sentinel: Data connectors → Microsoft Entra ID → confirm 'Connected' status."

    $results.Add((New-CheckResult `
        -CheckId 'SIM-003' `
        -Category 'Monitoring' `
        -Name 'Entra SIEM Integration via Diagnostic Settings' `
        -Status 'INFO' `
        -Detail $sim003Detail `
        -Recommendation 'Validate Entra ID diagnostic settings in the Azure portal. If not configured, create a diagnostic setting forwarding all identity log categories to your Log Analytics workspace.' `
        -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SIM-004: Continuous Access Evaluation (CAE) enabled
    # Get-MgPolicyContinuousAccessEvaluationPolicy (v1.0 endpoint)
    # -------------------------------------------------------------------------
    try {
        $caePolicy = Get-MgPolicyContinuousAccessEvaluationPolicy -ErrorAction Stop

        $caeIsEnabled     = $caePolicy.IsEnabled
        $caeMigrateState  = $caePolicy.Migrate

        if (-not $caeIsEnabled) {
            $sim004Status = 'MEDIUM'
            $sim004Detail = 'Continuous Access Evaluation (CAE) is disabled. Sessions may remain valid for up to 1 hour after account compromise, MFA requirement changes, or device compliance changes.'
        }
        elseif ($caeMigrateState -eq $false -or $caeMigrateState -eq 'disabled') {
            $sim004Status = 'LOW'
            $sim004Detail = 'CAE is enabled but not in strict mode. In strict mode, session token lifetime is capped at 1 hour; in standard mode it is up to 1 day for some clients.'
        }
        else {
            $sim004Status = 'PASS'
            $sim004Detail = "CAE is enabled. Mode: $(if ($caeMigrateState) { 'strict (recommended)' } else { 'standard' })."
        }
    }
    catch {
        $sim004Status = 'MEDIUM'
        $sim004Detail = "CAE policy could not be retrieved. Error: $_. Verify in Entra portal: Identity → Protection → Continuous access evaluation."
    }

    $results.Add((New-CheckResult `
        -CheckId 'SIM-004' `
        -Category 'Monitoring' `
        -Name 'Continuous Access Evaluation (CAE) Enabled' `
        -Status $sim004Status `
        -Detail $sim004Detail `
        -Recommendation "Enable CAE in strict mode (Entra ID → Protection → Continuous access evaluation → Strict enforcement). CAE causes instant revocation of session tokens when user risk, location, or compliance changes." `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/concept-continuous-access-evaluation' `
        -CISControl '' -SC300Domain 'Authentication & Access Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
