#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Microsoft Secure Score: current score, unaddressed improvement actions,
    30-day trend, and comparison to industry average.

.DESCRIPTION
    Test-SecureScore retrieves the tenant's Microsoft Secure Score and evaluates
    the current percentage against thresholds, counts unaddressed high-priority
    improvement actions, analyzes the 30-day score trend, and compares the tenant
    score to similar organizations using the averageComparativeScores field.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        SecurityEvents.Read.All  or  SecurityIncident.Read.All

    License Required: E3 minimum
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
#>

function Test-SecureScore {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve current Secure Score
    # -------------------------------------------------------------------------
    $latestScore = $null
    try {
        $scoreUri = 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1'
        $scoreResp = Invoke-MgGraphRequest -Method GET -Uri $scoreUri -ErrorAction Stop
        if ($scoreResp.value -and $scoreResp.value.Count -gt 0) {
            $latestScore = $scoreResp.value[0]
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'SCR-000' `
            -Category 'Monitoring' `
            -Name 'Secure Score Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: SecurityEvents.Read.All. Error: $_" `
            -Recommendation 'Grant SecurityEvents.Read.All to the service principal.' `
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
    $currentScore = [double]$latestScore.currentScore
    $maxScore     = [double]$latestScore.maxScore
    $scorePct     = if ($maxScore -gt 0) { [math]::Round(($currentScore / $maxScore) * 100, 1) } else { 0 }
    $scoreDate    = $latestScore.createdDateTime

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
    # -------------------------------------------------------------------------
    try {
        $controlsUri = 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=250'
        $controlsResp = Invoke-MgGraphRequest -Method GET -Uri $controlsUri -ErrorAction Stop
        $controls = [System.Collections.Generic.List[object]]::new()
        foreach ($c in $controlsResp.value) { $controls.Add($c) }
        $nextLink = $controlsResp.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($c in $page.value) { $controls.Add($c) }
            $nextLink = $page.'@odata.nextLink'
        }

        # 'Default' state = not yet addressed
        $unaddressed = @($controls | Where-Object { $_.implementationStatus -eq 'Default' -or $_.controlStateUpdates.Count -eq 0 })

        # Filter for high-severity controls
        $highSeverityUnaddressed = @($controls | Where-Object {
            ($_.implementationStatus -eq 'Default' -or $_.controlStateUpdates.Count -eq 0) -and
            ($_.rank -le 20 -or $_.maxScore -ge 10)  # High-value controls
        })

        $scr002Status = if ($highSeverityUnaddressed.Count -gt 20) { 'HIGH' }
                        elseif ($highSeverityUnaddressed.Count -gt 10) { 'MEDIUM' }
                        else { 'PASS' }

        $topUnaddressed = $highSeverityUnaddressed | Sort-Object maxScore -Descending |
                          Select-Object -First 10 | ForEach-Object { "$($_.title) (+$($_.maxScore) pts)" }

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
            -Recommendation 'Grant SecurityEvents.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-improvement-actions' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SCR-003: Secure Score trend (last 30 days)
    # -------------------------------------------------------------------------
    try {
        $historicalUri = 'https://graph.microsoft.com/v1.0/security/secureScores?$top=10'
        $historicalResp = Invoke-MgGraphRequest -Method GET -Uri $historicalUri -ErrorAction Stop
        $historicalScores = $historicalResp.value

        if ($historicalScores.Count -ge 2) {
            # Scores are returned newest-first
            $newest = $historicalScores[0]
            $oldest = $historicalScores[-1]

            $newestPct = if ($newest.maxScore -gt 0) { [math]::Round(($newest.currentScore / $newest.maxScore) * 100, 1) } else { 0 }
            $oldestPct = if ($oldest.maxScore -gt 0) { [math]::Round(($oldest.currentScore / $oldest.maxScore) * 100, 1) } else { 0 }
            $trend     = [math]::Round($newestPct - $oldestPct, 1)
            $trendText = if ($trend -gt 0) { "+$trend% (improving)" } elseif ($trend -lt 0) { "$trend% (declining)" } else { 'stable (no change)' }

            $scoreTrend = $historicalScores | ForEach-Object {
                "$($_.createdDateTime.Substring(0,10)): $([math]::Round(($_.currentScore / $_.maxScore) * 100, 1))%"
            }

            $scr003Detail = "Score trend over last $($historicalScores.Count) data points: $trendText. Points: $($scoreTrend -join ', ')."
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
            -Recommendation 'Monitor Secure Score weekly. A declining trend indicates controls are being disabled or new risks are being introduced. Set up a weekly report in the Defender portal.' `
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
            -Recommendation 'Grant SecurityEvents.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score-history-metrics-trends' `
            -CISControl '' -SC300Domain 'Monitoring & Alerting' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SCR-004: Secure Score vs. industry/similar organizations comparison
    # -------------------------------------------------------------------------
    $comparativeScores = $latestScore.averageComparativeScores
    if ($comparativeScores -and $comparativeScores.Count -gt 0) {
        $comparisons = $comparativeScores | ForEach-Object {
            $compPct = if ($_.maxScore -gt 0) { [math]::Round(($_.averageScore / $_.maxScore) * 100, 1) } else { [math]::Round($_.averageScore, 1) }
            "$($_.basis): avg $compPct%"
        }

        $industryComp = $comparativeScores | Where-Object { $_.basis -match 'industry|seatsize|allTenants' } | Select-Object -First 1
        $tenantVsIndustry = if ($industryComp) {
            $indAvg = $industryComp.averageScore
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
