#Requires -Version 7.0

<#
.SYNOPSIS
    Generates an HTML and JSON security assessment report from check results.

.DESCRIPTION
    Accepts an array of PSCustomObjects produced by New-CheckResult, calculates a
    risk score, builds per-category finding cards, and writes two output files:
    - <OutputPath>/<TenantId>_<date>.html  — self-contained HTML report
    - <OutputPath>/<TenantId>_<date>.json  — machine-readable export with metadata

    The HTML template is loaded from reports/template.html relative to the scripts/
    directory. If the template file is not found, an inline fallback is used so the
    function never fails due to a missing template.

.PARAMETER Results
    Array of PSCustomObjects from New-CheckResult.

.PARAMETER OutputPath
    Directory where the HTML and JSON files will be written.

.PARAMETER TenantId
    Tenant ID written into the report metadata.

.PARAMETER TenantName
    Human-readable tenant name (e.g. "Contoso GmbH").

.PARAMETER AssessmentDuration
    Timespan of the assessment run, formatted as string (e.g. "00:02:34").

.EXAMPLE
    New-AssessmentReport -Results $allResults -OutputPath ./reports -TenantId $tid -TenantName "Contoso" -AssessmentDuration "00:01:47"
#>
function New-AssessmentReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [string]$TenantName = '',

        [string]$AssessmentDuration = 'N/A'
    )

    # ---- Normalize legacy result objects ------------------------------------
    # Modules that use the old New-AssessmentResult signature (Status=Pass/Fail/Warning/Info
    # + separate Severity field) are converted to the canonical format here so the rest of
    # the function only deals with one shape.
    $Results = $Results | ForEach-Object {
        if ($_.Status -in @('Pass','Fail','Warning','Info')) {
            $newStatus = switch -Regex ("$($_.Status)|$($_.Severity)") {
                '(?i)Fail.*Critical'    { 'CRITICAL'; break }
                '(?i)Fail.*High'        { 'HIGH';     break }
                '(?i)Fail.*Medium'      { 'MEDIUM';   break }
                '(?i)Fail.*Low'         { 'LOW';      break }
                '(?i)Warning.*Critical' { 'HIGH';     break }
                '(?i)Warning.*High'     { 'HIGH';     break }
                '(?i)Warning.*Medium'   { 'MEDIUM';   break }
                '(?i)Warning.*Low'      { 'LOW';      break }
                '(?i)^Pass'             { 'PASS';     break }
                '(?i)^Info'             { 'INFO';     break }
                default                 { 'INFO' }
            }
            $rawName = if ($_.CheckName) { $_.CheckName } else { $_.Name }
            $checkId = ''
            $checkName = $rawName
            if ($rawName -match '^([A-Z]+-\d+):\s*(.+)$') {
                $checkId   = $Matches[1]
                $checkName = $Matches[2]
            }
            [PSCustomObject]@{
                CheckId         = if ($_.CheckId) { $_.CheckId } else { $checkId }
                Category        = $_.Category
                Name            = $checkName
                Status          = $newStatus
                Detail          = $_.Detail
                Recommendation  = $_.Recommendation
                Reference       = $_.Reference
                CISControl      = if ($_.CISControl) { $_.CISControl } elseif ($_.CisControl) { $_.CisControl } else { '' }
                SC300Domain     = if ($_.SC300Domain) { $_.SC300Domain } else { '' }
                LicenseRequired = if ($_.LicenseRequired) { $_.LicenseRequired } else { 'None' }
                AffectedObjects = if ($_.AffectedObjects) { $_.AffectedObjects } else { @() }
                Timestamp       = $_.Timestamp
            }
        } else {
            $_
        }
    }

    # ---- Score calculation -----------------------------------------------
    # Each finding of severity adds points, capped at 100.
    # PASS findings reduce the score slightly (reward good posture).
    $rawScore = 0
    foreach ($r in $Results) {
        switch ($r.Status) {
            'CRITICAL' { $rawScore += 20 }
            'HIGH'     { $rawScore += 10 }
            'MEDIUM'   { $rawScore += 5  }
            'LOW'      { $rawScore += 1  }
        }
    }
    $passCount     = ($Results | Where-Object Status -eq 'PASS').Count
    $reduction     = [Math]::Floor($passCount * 0.5)   # each PASS reduces by 0.5, floor
    $riskScore     = [Math]::Max(0, [Math]::Min(100, $rawScore - $reduction))

    $riskLevel = switch ($true) {
        ($riskScore -le 20) { 'LOW RISK'      }
        ($riskScore -le 50) { 'MEDIUM RISK'   }
        ($riskScore -le 80) { 'HIGH RISK'     }
        default             { 'CRITICAL RISK' }
    }
    $riskColor = switch ($riskLevel) {
        'LOW RISK'      { '#28a745' }
        'MEDIUM RISK'   { '#fd7e14' }
        'HIGH RISK'     { '#e65c00' }
        'CRITICAL RISK' { '#dc3545' }
    }

    # ---- Status counts -------------------------------------------------------
    $criticalCount = ($Results | Where-Object Status -eq 'CRITICAL').Count
    $highCount     = ($Results | Where-Object Status -eq 'HIGH').Count
    $mediumCount   = ($Results | Where-Object Status -eq 'MEDIUM').Count
    $lowCount      = ($Results | Where-Object Status -eq 'LOW').Count
    $infoCount     = ($Results | Where-Object Status -eq 'INFO').Count
    $totalCount    = $Results.Count

    # ---- Build findings HTML ------------------------------------------------
    $statusBadgeColor = @{
        CRITICAL = '#dc3545'
        HIGH     = '#e65c00'
        MEDIUM   = '#fd7e14'
        LOW      = '#0078D4'
        INFO     = '#6c757d'
        PASS     = '#28a745'
    }
    $licenseBadgeColor = @{
        E3   = '#0078D4'
        E5   = '#6f42c1'
        Both = '#20c997'
        None = '#6c757d'
    }

    $categories = $Results | Select-Object -ExpandProperty Category -Unique | Sort-Object
    $findingsHtmlParts = [System.Collections.Generic.List[string]]::new()

    foreach ($category in $categories) {
        $catResults   = $Results | Where-Object Category -eq $category
        $catId        = $category -replace '[^a-zA-Z0-9]', '_'
        $catCritical  = ($catResults | Where-Object Status -eq 'CRITICAL').Count
        $catHigh      = ($catResults | Where-Object Status -eq 'HIGH').Count
        $catBadge     = if ($catCritical -gt 0) { "<span class='badge badge-critical'>$catCritical CRITICAL</span>" }
                        elseif ($catHigh -gt 0)  { "<span class='badge badge-high'>$catHigh HIGH</span>" }
                        else                     { "<span class='badge badge-pass'>OK</span>" }

        $cardsParts = [System.Collections.Generic.List[string]]::new()
        foreach ($r in $catResults) {
            $badgeColor  = $statusBadgeColor[$r.Status]
            $licColor    = $licenseBadgeColor[$r.LicenseRequired]
            $affectedHtml = if ($r.AffectedObjects -and $r.AffectedObjects.Count -gt 0) {
                $items = ($r.AffectedObjects | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join ''
                "<div class='affected-list'><strong>Affected Objects:</strong><ul>$items</ul></div>"
            } else { '' }

            $refHtml = if ($r.Reference) {
                "<a class='ref-link' href='$($r.Reference)' target='_blank' rel='noopener'>$($r.Reference)</a>"
            } else { '' }

            $cardsParts.Add(@"
<div class='finding-card' data-status='$($r.Status)' data-category='$([System.Web.HttpUtility]::HtmlEncode($category))'>
  <div class='finding-header'>
    <span class='status-badge' style='background:$badgeColor;'>$($r.Status)</span>
    <span class='check-id'>$([System.Web.HttpUtility]::HtmlEncode($r.CheckId))</span>
    <span class='check-name'>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</span>
    <span class='license-badge' style='background:$licColor;'>$($r.LicenseRequired)</span>
  </div>
  <div class='finding-body'>
    <p class='detail'>$([System.Web.HttpUtility]::HtmlEncode($r.Detail))</p>
    $affectedHtml
    <div class='recommendation'><strong>Recommendation:</strong> $([System.Web.HttpUtility]::HtmlEncode($r.Recommendation))</div>
    <div class='meta-row'>
      <span class='meta-item'><strong>CIS:</strong> $([System.Web.HttpUtility]::HtmlEncode($r.CISControl))</span>
      <span class='meta-item'><strong>SC-300:</strong> $([System.Web.HttpUtility]::HtmlEncode($r.SC300Domain))</span>
    </div>
    <div class='ref-row'>$refHtml</div>
  </div>
</div>
"@)
        }

        $findingsHtmlParts.Add(@"
<div class='accordion' id='acc-$catId'>
  <div class='accordion-header' onclick='toggleAccordion("acc-$catId")'>
    <span class='acc-icon'>&#9654;</span>
    <span class='acc-title'>$([System.Web.HttpUtility]::HtmlEncode($category))</span>
    <span class='acc-count'>$($catResults.Count) checks</span>
    $catBadge
  </div>
  <div class='accordion-body'>
    $($cardsParts -join "`n")
  </div>
</div>
"@)
    }

    $findingsHtml = $findingsHtmlParts -join "`n"

    # Chart data for JS (severity distribution as JSON array for inline chart)
    $chartData = "[{`"label`":`"CRITICAL`",`"value`":$criticalCount,`"color`":`"#dc3545`"},{`"label`":`"HIGH`",`"value`":$highCount,`"color`":`"#e65c00`"},{`"label`":`"MEDIUM`",`"value`":$mediumCount,`"color`":`"#fd7e14`"},{`"label`":`"LOW`",`"value`":$lowCount,`"color`":`"#0078D4`"},{`"label`":`"INFO`",`"value`":$infoCount,`"color`":`"#6c757d`"},{`"label`":`"PASS`",`"value`":$passCount,`"color`":`"#28a745`"}]"

    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $safeDate   = Get-Date -Format 'yyyyMMdd_HHmmss'

    # ---- Load template -------------------------------------------------------
    $templatePath = Join-Path $PSScriptRoot '..\..\reports\template.html'
    if (-not (Test-Path $templatePath)) {
        # Fallback: try alternate relative path from scripts/helpers/
        $templatePath = Join-Path $PSScriptRoot '..\..\..\reports\template.html'
    }

    if (Test-Path $templatePath) {
        $htmlTemplate = Get-Content -Path $templatePath -Raw -Encoding UTF8
    }
    else {
        # Inline fallback template (minimal, functional)
        $htmlTemplate = Get-InlineFallbackTemplate
    }

    # ---- Replace placeholders -----------------------------------------------
    $html = $htmlTemplate `
        -replace '\{\{REPORT_DATE\}\}',         $reportDate `
        -replace '\{\{TENANT_ID\}\}',           ([System.Web.HttpUtility]::HtmlEncode($TenantId)) `
        -replace '\{\{TENANT_NAME\}\}',         ([System.Web.HttpUtility]::HtmlEncode($TenantName)) `
        -replace '\{\{RISK_SCORE\}\}',          $riskScore `
        -replace '\{\{RISK_LEVEL\}\}',          $riskLevel `
        -replace '\{\{RISK_COLOR\}\}',          $riskColor `
        -replace '\{\{CRITICAL_COUNT\}\}',      $criticalCount `
        -replace '\{\{HIGH_COUNT\}\}',          $highCount `
        -replace '\{\{MEDIUM_COUNT\}\}',        $mediumCount `
        -replace '\{\{LOW_COUNT\}\}',           $lowCount `
        -replace '\{\{INFO_COUNT\}\}',          $infoCount `
        -replace '\{\{PASS_COUNT\}\}',          $passCount `
        -replace '\{\{TOTAL_COUNT\}\}',         $totalCount `
        -replace '\{\{ASSESSMENT_DURATION\}\}', ([System.Web.HttpUtility]::HtmlEncode($AssessmentDuration)) `
        -replace '\{\{FINDINGS_HTML\}\}',       $findingsHtml `
        -replace '\{\{CHART_DATA\}\}',          $chartData

    # ---- Write output files --------------------------------------------------
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $baseName    = "${TenantId}_${safeDate}"
    $htmlFile    = Join-Path $OutputPath "$baseName.html"
    $jsonFile    = Join-Path $OutputPath "$baseName.json"

    $html | Out-File -FilePath $htmlFile -Encoding UTF8 -Force

    # JSON export
    $jsonPayload = [PSCustomObject]@{
        Metadata = [PSCustomObject]@{
            TenantId           = $TenantId
            TenantName         = $TenantName
            ReportDate         = $reportDate
            AssessmentDuration = $AssessmentDuration
            Version            = '1.0.0'
            RiskScore          = $riskScore
            RiskLevel          = $riskLevel
            TotalChecks        = $totalCount
            StatusCounts       = [PSCustomObject]@{
                CRITICAL = $criticalCount
                HIGH     = $highCount
                MEDIUM   = $mediumCount
                LOW      = $lowCount
                INFO     = $infoCount
                PASS     = $passCount
            }
        }
        Results = $Results
    }
    $jsonPayload | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFile -Encoding UTF8 -Force

    Write-Host "HTML report: $htmlFile" -ForegroundColor Green
    Write-Host "JSON export: $jsonFile" -ForegroundColor Green

    return [PSCustomObject]@{
        HtmlPath = $htmlFile
        JsonPath = $jsonFile
        RiskScore = $riskScore
        RiskLevel = $riskLevel
    }
}

# Internal helper: returns a minimal inline HTML template when reports/template.html is missing.
function Get-InlineFallbackTemplate {
    return @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Security Assessment</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#e6edf3;font-size:15px}
.header{background:#161b22;border-bottom:1px solid #30363d;padding:24px 40px}
.header h1{color:#e6edf3;font-size:1.6em;font-weight:600}
.header .sub{color:#8b949e;margin-top:4px;font-size:0.9em}
.container{max-width:1100px;margin:0 auto;padding:32px 24px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:32px}
.meta-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.meta-card label{font-size:0.75em;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
.meta-card p{font-size:1.05em;font-weight:600;margin-top:4px;color:#e6edf3;word-break:break-all}
.score-section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;margin-bottom:32px;text-align:center}
.score-ring{display:inline-block;width:120px;height:120px;border-radius:50%;border:8px solid {{RISK_COLOR}};line-height:104px;font-size:2.2em;font-weight:700;color:{{RISK_COLOR}};margin-bottom:12px}
.risk-label{font-size:1.1em;font-weight:600;color:{{RISK_COLOR}}}
.counts-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:32px}
.count-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center}
.count-card .num{font-size:2em;font-weight:700}
.count-card .lbl{font-size:0.8em;color:#8b949e;margin-top:2px}
.filter-bar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px;align-items:center}
.filter-btn{border:1px solid #30363d;background:#161b22;color:#e6edf3;padding:6px 14px;border-radius:20px;cursor:pointer;font-size:0.85em;transition:background .15s}
.filter-btn:hover,.filter-btn.active{background:#0078D4;border-color:#0078D4}
.search-box{margin-left:auto;padding:6px 12px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:0.9em;width:220px}
.search-box:focus{outline:none;border-color:#0078D4}
.category-filter{padding:6px 12px;border-radius:6px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:0.9em}
.accordion{background:#161b22;border:1px solid #30363d;border-radius:8px;margin-bottom:12px;overflow:hidden}
.accordion-header{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer;user-select:none;transition:background .15s}
.accordion-header:hover{background:#1c2128}
.acc-icon{color:#8b949e;transition:transform .2s;display:inline-block}
.acc-icon.open{transform:rotate(90deg)}
.acc-title{font-weight:600;font-size:1em;flex:1}
.acc-count{color:#8b949e;font-size:0.85em}
.accordion-body{display:none;padding:0 16px 16px}
.accordion-body.open{display:block}
.badge{font-size:0.75em;padding:2px 8px;border-radius:10px;font-weight:600}
.badge-critical{background:#dc354520;color:#dc3545;border:1px solid #dc354540}
.badge-high{background:#e65c0020;color:#e65c00;border:1px solid #e65c0040}
.badge-pass{background:#28a74520;color:#28a745;border:1px solid #28a74540}
.finding-card{border:1px solid #30363d;border-radius:6px;padding:16px;margin-top:10px;transition:border-color .15s}
.finding-card:hover{border-color:#0078D4}
.finding-header{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.status-badge{font-size:0.78em;padding:3px 10px;border-radius:12px;font-weight:700;color:#fff}
.check-id{font-family:monospace;font-size:0.85em;color:#8b949e;background:#0d1117;padding:2px 6px;border-radius:4px}
.check-name{font-weight:600;flex:1}
.license-badge{font-size:0.75em;padding:2px 8px;border-radius:10px;color:#fff;font-weight:600}
.detail{color:#c9d1d9;line-height:1.5;margin-bottom:10px}
.affected-list{font-size:0.88em;background:#0d1117;border-radius:6px;padding:10px 14px;margin-bottom:10px}
.affected-list ul{margin-left:18px;margin-top:4px;color:#8b949e}
.recommendation{background:#0d1117;border-left:3px solid #0078D4;padding:10px 14px;border-radius:0 6px 6px 0;margin-bottom:10px;font-size:0.9em;color:#c9d1d9}
.meta-row{display:flex;gap:18px;flex-wrap:wrap;font-size:0.83em;color:#8b949e;margin-bottom:6px}
.ref-link{font-size:0.83em;color:#0078D4;text-decoration:none;word-break:break-all}
.ref-link:hover{text-decoration:underline}
.footer{text-align:center;padding:32px 20px;color:#6e7681;font-size:0.83em;border-top:1px solid #21262d;margin-top:32px}
@media(max-width:700px){.counts-grid{grid-template-columns:repeat(3,1fr)}.filter-bar{flex-direction:column;align-items:stretch}.search-box{width:100%;margin-left:0}}
@media print{.filter-bar,.accordion-header{display:none!important}.accordion-body{display:block!important}.finding-card{break-inside:avoid}body{background:#fff;color:#000}.header{background:#0078D4}}
</style>
</head>
<body>
<div class="header">
  <h1>M365 Security Assessment Report</h1>
  <div class="sub">Tenant: {{TENANT_NAME}} &nbsp;|&nbsp; {{TENANT_ID}} &nbsp;|&nbsp; {{REPORT_DATE}} &nbsp;|&nbsp; Duration: {{ASSESSMENT_DURATION}}</div>
</div>
<div class="container">
  <div class="meta-grid">
    <div class="meta-card"><label>Tenant</label><p>{{TENANT_NAME}}</p></div>
    <div class="meta-card"><label>Tenant ID</label><p>{{TENANT_ID}}</p></div>
    <div class="meta-card"><label>Report Date</label><p>{{REPORT_DATE}}</p></div>
    <div class="meta-card"><label>Duration</label><p>{{ASSESSMENT_DURATION}}</p></div>
  </div>

  <div class="score-section">
    <div class="score-ring">{{RISK_SCORE}}</div>
    <div class="risk-label">{{RISK_LEVEL}}</div>
  </div>

  <div class="counts-grid">
    <div class="count-card"><div class="num" style="color:#dc3545">{{CRITICAL_COUNT}}</div><div class="lbl">CRITICAL</div></div>
    <div class="count-card"><div class="num" style="color:#e65c00">{{HIGH_COUNT}}</div><div class="lbl">HIGH</div></div>
    <div class="count-card"><div class="num" style="color:#fd7e14">{{MEDIUM_COUNT}}</div><div class="lbl">MEDIUM</div></div>
    <div class="count-card"><div class="num" style="color:#0078D4">{{LOW_COUNT}}</div><div class="lbl">LOW</div></div>
    <div class="count-card"><div class="num" style="color:#6c757d">{{INFO_COUNT}}</div><div class="lbl">INFO</div></div>
    <div class="count-card"><div class="num" style="color:#28a745">{{PASS_COUNT}}</div><div class="lbl">PASS</div></div>
  </div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterSeverity('ALL')">All ({{TOTAL_COUNT}})</button>
    <button class="filter-btn" onclick="filterSeverity('CRITICAL')" style="border-color:#dc3545">CRITICAL</button>
    <button class="filter-btn" onclick="filterSeverity('HIGH')" style="border-color:#e65c00">HIGH</button>
    <button class="filter-btn" onclick="filterSeverity('MEDIUM')" style="border-color:#fd7e14">MEDIUM</button>
    <button class="filter-btn" onclick="filterSeverity('LOW')" style="border-color:#0078D4">LOW</button>
    <button class="filter-btn" onclick="filterSeverity('INFO')" style="border-color:#6c757d">INFO</button>
    <button class="filter-btn" onclick="filterSeverity('PASS')" style="border-color:#28a745">PASS</button>
    <select class="category-filter" onchange="filterCategory(this.value)" id="catFilter">
      <option value="ALL">All Categories</option>
    </select>
    <input class="search-box" type="text" placeholder="Search findings..." oninput="filterSearch(this.value)" />
  </div>

  <div id="findings-container">
    {{FINDINGS_HTML}}
  </div>
</div>
<div class="footer">
  Generated by M365 Security Assessment Framework v1.0.0 &nbsp;|&nbsp; github.com/yusufxsert/m365-security-assessment &nbsp;|&nbsp; {{REPORT_DATE}}
</div>
<script>
var currentSeverity = 'ALL';
var currentCategory = 'ALL';
var currentSearch   = '';
var chartData = {{CHART_DATA}};

// Populate category dropdown
(function() {
  var cats = {};
  document.querySelectorAll('.finding-card').forEach(function(c) {
    var cat = c.getAttribute('data-category');
    if (cat) cats[cat] = true;
  });
  var sel = document.getElementById('catFilter');
  Object.keys(cats).sort().forEach(function(cat) {
    var opt = document.createElement('option');
    opt.value = cat;
    opt.textContent = cat;
    sel.appendChild(opt);
  });
})();

function applyFilters() {
  document.querySelectorAll('.accordion').forEach(function(acc) {
    var cards = acc.querySelectorAll('.finding-card');
    var accVisible = false;
    cards.forEach(function(card) {
      var status   = card.getAttribute('data-status') || '';
      var category = card.getAttribute('data-category') || '';
      var text     = card.textContent.toLowerCase();
      var sevOk  = currentSeverity === 'ALL' || status === currentSeverity;
      var catOk  = currentCategory === 'ALL' || category === currentCategory;
      var srchOk = currentSearch === '' || text.indexOf(currentSearch.toLowerCase()) !== -1;
      var show   = sevOk && catOk && srchOk;
      card.style.display = show ? '' : 'none';
      if (show) accVisible = true;
    });
    acc.style.display = accVisible ? '' : 'none';
    if (accVisible) {
      acc.querySelector('.accordion-body').classList.add('open');
      var icon = acc.querySelector('.acc-icon');
      if (icon) icon.classList.add('open');
    }
  });
}

function filterSeverity(sev) {
  currentSeverity = sev;
  document.querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  event.target.classList.add('active');
  applyFilters();
}

function filterCategory(cat) {
  currentCategory = cat;
  applyFilters();
}

function filterSearch(val) {
  currentSearch = val;
  applyFilters();
}

function toggleAccordion(id) {
  var acc  = document.getElementById(id);
  var body = acc.querySelector('.accordion-body');
  var icon = acc.querySelector('.acc-icon');
  body.classList.toggle('open');
  icon.classList.toggle('open');
}
</script>
</body>
</html>
'@
}
