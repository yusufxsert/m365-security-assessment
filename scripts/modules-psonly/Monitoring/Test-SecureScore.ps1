#Requires -Version 7.0

<#
.SYNOPSIS
    Audits Microsoft Secure Score: current score, improvement actions, trend, industry comparison. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgSecuritySecureScore and
    Get-MgSecuritySecureScoreControlProfile instead of raw Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    The Microsoft.Graph.Security module exposes these as strongly-typed cmdlets with
    automatic pagination. Get-MgSecuritySecureScore -Top 1 returns the most recent
    score record. Get-MgSecuritySecureScoreControlProfile -All returns all control
    profiles with their implementation status, titles, and point values.

    SEE ALSO (Graph variant):
        scripts/modules/Monitoring/Test-SecureScore.ps1

    Required connection:
        Connect-MgGraph -Scopes "SecurityEvents.Read.All"

    Required scopes:
        SecurityEvents.Read.All  OR  SecurityIncident.Read.All

    Required modules:
        Microsoft.Graph.Security

    License: E3 minimum
    SC-300 Domain: Monitoring & Alerting

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-SecureScore {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve current Secure Score via Get-MgSecuritySecureScore -Top 1
    # -------------------------------------------------------------------------
    $latestScore = $null
    try {
        $latestScore = Get-MgSecuritySecureScore -Top 1 -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'SCR-000' `
            -Category 'Monitoring' `
            -Name 'Secure Score Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: SecurityEvents.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "SecurityEvents.Read.All".' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    if ($null -eq $latestScore) {
        $results.Add((New-CheckResult `
            -CheckId 'SCR-001' `
            -Category 'Monitoring' `
            -Name 'Microsoft Secure Score' `
            -Status 'INFO' `
            -Detail 'No Secure Score data available. The tenant may not have Secure Score enabled yet.' `
            -Recommendation 'Navigate to https://security.microsoft.com/securescore to initialize Secure Score for the tenant.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # SCR-001: Current Secure Score
    # -------------------------------------------------------------------------
    $currentScore = [double]$latestScore.CurrentScore
    $maxScore     = [double]$latestScore.MaxScore
    $scorePct     = if ($maxScore -gt 0) { [math]::Round(($currentScore / $maxScore) * 100, 1) } else { 0 }
    $scoreDate    = $latestScore.CreatedDateTime

    if ($scorePct -lt 30) {
        $scr001Status = 'HIGH'
    }
    elseif ($scorePct -lt 50) {
        $scr001Status = 'MEDIUM'
    }
    else {
        $scr001Status = 'PASS'
    }

    $results.Add((New-CheckResult `
        -CheckId 'SCR-001' `
        -Category 'Monitoring' `
        -Name 'Microsoft Secure Score — Current Score' `
        -Status $scr001Status `
        -Detail "Current Secure Score: $currentScore / $maxScore ($scorePct%) as of $scoreDate. Scores below 50% indicate significant unaddressed security controls." `
        -Recommendation 'Target a Secure Score of at least 50% as a baseline. Prioritize improvement actions tagged as high severity and low implementation effort. Review weekly.' `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SCR-002: Unaddressed improvement actions (high priority)
    # Uses Get-MgSecuritySecureScoreControlProfile -All
    # -------------------------------------------------------------------------
    try {
        $controls = Get-MgSecuritySecureScoreControlProfile -All -ErrorAction Stop

        # 'Default' state = not yet addressed
        $unaddressed = @($controls | Where-Object {
            $_.ImplementationStatus -eq 'Default' -or
            ($null -eq $_.ControlStateUpdates -or $_.ControlStateUpdates.Count -eq 0)
        })

        # Filter for high-value controls
        $highSeverityUnaddressed = @($controls | Where-Object {
            ($_.ImplementationStatus -eq 'Default' -or
             ($null -eq $_.ControlStateUpdates -or $_.ControlStateUpdates.Count -eq 0)) -and
            ($_.Rank -le 20 -or $_.MaxScore -ge 10)
        })

        $scr002Status = if ($highSeverityUnaddressed.Count -gt 20) { 'HIGH' }
                        elseif ($highSeverityUnaddressed.Count -gt 10) { 'MEDIUM' }
                        else { 'PASS' }

        $topUnaddressed = $highSeverityUnaddressed |
            Sort-Object MaxScore -Descending |
            Select-Object -First 10 |
            ForEach-Object { "$($_.Title) (+$($_.MaxScore) pts)" }

        $results.Add((New-CheckResult `
            -CheckId 'SCR-002' `
            -Category 'Monitoring' `
            -Name 'Secure Score — Unaddressed Improvement Actions' `
            -Status $scr002Status `
            -Detail "Total unaddressed controls: $($unaddressed.Count). High-value unaddressed (maxScore >= 10 pts): $($highSeverityUnaddressed.Count). Top items: $($topUnaddressed -join '; ')." `
            -Recommendation 'Work through improvement actions ordered by maxScore. Focus first on controls that are easy to implement and have high point value. Use the Secure Score portal for implementation guidance.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-improvement-actions' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @($topUnaddressed)))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'SCR-002' `
            -Category 'Monitoring' `
            -Name 'Secure Score — Unaddressed Improvement Actions' `
            -Status 'INFO' `
            -Detail "Improvement actions check skipped: API error. Required: SecurityEvents.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "SecurityEvents.Read.All".' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-improvement-actions' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SCR-003: Secure Score trend (last available data points)
    # Get-MgSecuritySecureScore without -Top returns recent history
    # -------------------------------------------------------------------------
    try {
        $historicalScores = Get-MgSecuritySecureScore -Top 10 -ErrorAction Stop

        if ($historicalScores -and $historicalScores.Count -ge 2) {
            # Scores are returned newest-first
            $newestArr = @($historicalScores)
            $newest = $newestArr[0]
            $oldest = $newestArr[-1]

            $newestPct = if ($newest.MaxScore -gt 0) { [math]::Round(($newest.CurrentScore / $newest.MaxScore) * 100, 1) } else { 0 }
            $oldestPct = if ($oldest.MaxScore -gt 0) { [math]::Round(($oldest.CurrentScore / $oldest.MaxScore) * 100, 1) } else { 0 }
            $trend     = [math]::Round($newestPct - $oldestPct, 1)
            $trendText = if ($trend -gt 0) { "+$trend% (improving)" } elseif ($trend -lt 0) { "$trend% (declining)" } else { 'stable (no change)' }

            $scoreTrend = $newestArr | ForEach-Object {
                "$($_.CreatedDateTime.ToString('yyyy-MM-dd')): $([math]::Round(($_.CurrentScore / $_.MaxScore) * 100, 1))%"
            }

            $scr003Detail = "Score trend over last $($newestArr.Count) data points: $trendText. Points: $($scoreTrend -join ', ')."
        }
        else {
            $scr003Detail = "Only $($historicalScores.Count) historical data point(s) available — trend cannot be calculated. Score history builds over time."
        }

        $results.Add((New-CheckResult `
            -CheckId 'SCR-003' `
            -Category 'Monitoring' `
            -Name 'Secure Score Trend (Last 30 Days)' `
            -Status 'INFO' `
            -Detail $scr003Detail `
            -Recommendation 'Monitor Secure Score weekly. A declining trend indicates controls are being disabled or new risks are being introduced.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-history-metrics-trends' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'SCR-003' `
            -Category 'Monitoring' `
            -Name 'Secure Score Trend (Last 30 Days)' `
            -Status 'INFO' `
            -Detail "Score history check skipped: API error. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "SecurityEvents.Read.All".' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-history-metrics-trends' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SCR-004: Secure Score vs. industry/similar organizations comparison
    # averageComparativeScores is a property on the score record object
    # -------------------------------------------------------------------------
    $comparativeScores = $latestScore.AverageComparativeScores
    if ($comparativeScores -and $comparativeScores.Count -gt 0) {
        $comparisons = $comparativeScores | ForEach-Object {
            $compPct = if ($_.MaxScore -gt 0) { [math]::Round(($_.AverageScore / $_.MaxScore) * 100, 1) } else { [math]::Round($_.AverageScore, 1) }
            "$($_.Basis): avg $compPct%"
        }

        $industryComp = $comparativeScores | Where-Object { $_.Basis -match 'industry|seatsize|allTenants' } | Select-Object -First 1
        $tenantVsIndustry = if ($industryComp) {
            $indAvg = $industryComp.AverageScore
            if ($currentScore -gt $indAvg) { "above industry average ($currentScore vs $([math]::Round($indAvg, 1)))" }
            elseif ($currentScore -lt $indAvg) { "below industry average ($currentScore vs $([math]::Round($indAvg, 1)))" }
            else { "at industry average ($currentScore)" }
        }
        else { 'industry comparison not available' }

        $scr004Detail = "Tenant score is $tenantVsIndustry. All comparisons: $($comparisons -join ', ')."
    }
    else {
        $scr004Detail = 'Comparative score data not available in this score record. It may populate after the tenant has been enrolled in Secure Score for longer.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'SCR-004' `
        -Category 'Monitoring' `
        -Name 'Secure Score — Industry Comparison' `
        -Status 'INFO' `
        -Detail $scr004Detail `
        -Recommendation 'Use the industry comparison to contextualize your security posture. Being below the industry average for your vertical is a meaningful risk indicator to present to leadership.' `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score' `
        -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
