#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    PowerShell-only variant of the M365 Security Assessment — no App Registration required.

.DESCRIPTION
    Start-M365Assessment-PSOnly is the interactive-login equivalent of Start-M365Assessment.ps1.
    Instead of a service principal with certificate or client secret, it uses delegated
    permissions via browser or device-code login.

    WHY THIS VARIANT EXISTS
    -----------------------
    The main Start-M365Assessment.ps1 requires an Entra ID App Registration with
    application-level permissions and a certificate or client secret. This is the
    recommended approach for automated, unattended runs (CI/CD, scheduled tasks).

    This PS-only variant is intended for:
      • Ad-hoc assessments where you do not want to create an App Registration
      • Environments where App Registrations are restricted by policy
      • Exchange Online checks that are only available via EXO PowerShell,
        not the Graph API (e.g. per-mailbox CAS settings, DKIM signing config,
        transport rules, anti-phishing policies)
      • Operators who prefer to run assessments under their own user context

    COMPARISON: GRAPH (APP) vs PS-ONLY (DELEGATED)
    ------------------------------------------------
    | Aspect              | App Registration (Graph)    | PS-Only (Delegated)        |
    |---------------------|-----------------------------|----------------------------|
    | Auth method         | Certificate / Client Secret | Interactive browser / MFA  |
    | App Registration    | Required                    | Not required               |
    | Automation          | Yes (unattended)            | No (requires user login)   |
    | EXO-native checks   | Limited (Graph EXO beta)    | Full via EXO PS module     |
    | Risk on breach      | Service principal secret    | User session token only    |
    | Scope creep risk    | App-level (broad)           | Delegated (user-bounded)   |
    | Audit log entries   | Application entries         | User entries (traceable)   |

    CHECKS NOT AVAILABLE IN PS-ONLY
    --------------------------------
    Some checks have no PowerShell cmdlet equivalent and require the Graph API:
      • Diagnostic Settings / SIEM integration (Azure Monitor API)
      • Intune / Endpoint configuration (Graph-only, no EXO alternative)
      • Full Identity Protection risk event detail

    These checks are included as INFO stubs in the PS-only output.

    MODULES REQUIRED (install once)
    --------------------------------
    Install-Module Microsoft.Graph.Authentication           -Scope CurrentUser
    Install-Module Microsoft.Graph.Identity.SignIns         -Scope CurrentUser
    Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
    Install-Module Microsoft.Graph.Users                    -Scope CurrentUser
    Install-Module Microsoft.Graph.Groups                   -Scope CurrentUser
    Install-Module Microsoft.Graph.Applications             -Scope CurrentUser
    Install-Module Microsoft.Graph.Reports                  -Scope CurrentUser
    Install-Module Microsoft.Graph.DeviceManagement         -Scope CurrentUser
    Install-Module ExchangeOnlineManagement                 -Scope CurrentUser

.PARAMETER UPN
    Admin UPN used for Exchange Online connection.
    Example: admin@contoso.onmicrosoft.com

.PARAMETER OutputPath
    Directory where the assessment report is written. Defaults to ./reports.

.PARAMETER UseDeviceCode
    Use device code flow (no browser). Required for SSH sessions or headless systems.

.PARAMETER ConnectExchange
    Connect to Exchange Online for EXO-native checks (recommended).

.PARAMETER ConnectIPPS
    Connect to Security & Compliance Center for DLP, Labels, and Audit checks.

.PARAMETER Modules
    List of module names to run. Defaults to all available modules.
    Example: -Modules @('EmailSecurity','Authentication','ConditionalAccess')

.EXAMPLE
    # Minimal — Graph only, interactive browser
    .\Start-M365Assessment-PSOnly.ps1 -UPN admin@contoso.com

    # Recommended — Graph + EXO
    .\Start-M365Assessment-PSOnly.ps1 -UPN admin@contoso.com -ConnectExchange

    # Full — all connections, headless
    .\Start-M365Assessment-PSOnly.ps1 -UPN admin@contoso.com -ConnectExchange -ConnectIPPS -UseDeviceCode

    # Only email checks
    .\Start-M365Assessment-PSOnly.ps1 -UPN admin@contoso.com -ConnectExchange -Modules @('EmailSecurity')

.NOTES
    See also: scripts/Start-M365Assessment.ps1  (App Registration / unattended variant)
    See also: scripts/modules-psonly/Connect-PSOnly.ps1
    Docs     : docs/permissions-setup.md

    Main differences vs Start-M365Assessment.ps1:
      - No -TenantId, -ClientId, -CertificateThumbprint parameters
      - Modules loaded from scripts/modules-psonly/ instead of scripts/modules/
      - New-CheckResult helper defined identically (same output format)
      - Reports are written to the same format — results are interchangeable
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UPN,

    [string]$OutputPath = './reports',

    [switch]$UseDeviceCode,
    [switch]$ConnectExchange,
    [switch]$ConnectIPPS,

    [string[]]$Modules = @()
)

$ErrorActionPreference = 'Stop'
$startTime = Get-Date

# ---- Shared helper: New-CheckResult (same schema as main variant) --------------
function New-CheckResult {
    param(
        [string]$CheckId,
        [string]$Category,
        [string]$Name,
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO','PASS')]
        [string]$Status,
        [string]$Detail,
        [string]$Recommendation,
        [string]$Reference,
        [string]$CISControl,
        [string]$SC300Domain,
        [ValidateSet('E3','E5','Both','None')]
        [string]$LicenseRequired = 'None',
        [string[]]$AffectedObjects = @(),
        [string]$MitreId     = '',
        [string]$MitreTactic = ''
    )
    [PSCustomObject]@{
        CheckId         = $CheckId
        Category        = $Category
        Name            = $Name
        Status          = $Status
        Detail          = $Detail
        Recommendation  = $Recommendation
        Reference       = $Reference
        CISControl      = $CISControl
        SC300Domain     = $SC300Domain
        LicenseRequired = $LicenseRequired
        AffectedObjects = $AffectedObjects
        MitreId         = $MitreId
        MitreTactic     = $MitreTactic
        Timestamp       = (Get-Date -Format 'o')
    }
}

# ---- Resolve output path -------------------------------------------------------
$resolvedOutput = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($resolvedOutput)) {
    $resolvedOutput = Join-Path $PSScriptRoot $resolvedOutput
}
if (-not (Test-Path $resolvedOutput)) {
    New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
}

# ---- Connect ------------------------------------------------------------------
$connectScript = Join-Path $PSScriptRoot 'modules-psonly\Connect-PSOnly.ps1'
if (-not (Test-Path $connectScript)) {
    $connectScript = Join-Path $PSScriptRoot 'modules-psonly/Connect-PSOnly.ps1'
}
. $connectScript

Connect-PSOnly -UPN $UPN -UseDeviceCode:$UseDeviceCode `
    -ConnectExchange:$ConnectExchange -ConnectIPPS:$ConnectIPPS

# ---- Discover and run modules -------------------------------------------------
$moduleRoot = Join-Path $PSScriptRoot 'modules-psonly'

$allModuleFiles = Get-ChildItem -Path $moduleRoot -Recurse -Filter 'Test-*.ps1' |
    Sort-Object FullName

if ($Modules.Count -gt 0) {
    $allModuleFiles = $allModuleFiles | Where-Object {
        $category = Split-Path (Split-Path $_.FullName -Parent) -Leaf
        $category -in $Modules
    }
}

$allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($moduleFile in $allModuleFiles) {
    $category = Split-Path (Split-Path $moduleFile.FullName -Parent) -Leaf
    Write-Host "`n[Assessment] Running: $($moduleFile.BaseName) ($category)" -ForegroundColor Cyan

    try {
        . $moduleFile.FullName
        $funcName = $moduleFile.BaseName
        if (Get-Command -Name $funcName -ErrorAction SilentlyContinue) {
            $moduleResults = & $funcName
            foreach ($r in $moduleResults) { $allResults.Add($r) }
            Write-Host "[Assessment] $funcName completed: $($moduleResults.Count) findings." -ForegroundColor Green
        }
        else {
            Write-Warning "Module $funcName loaded but function not found — skipped."
        }
    }
    catch {
        Write-Warning "Module $($moduleFile.BaseName) failed: $_"
    }
}

# ---- Report -------------------------------------------------------------------
$duration    = (Get-Date) - $startTime
$durationStr = '{0:D2}:{1:D2}:{2:D2}' -f [int]$duration.Hours, [int]$duration.Minutes, [int]$duration.Seconds
$tenantId    = if ($UPN -match '@(.+)$') { $Matches[1] } else { 'unknown' }

$helperReport = Join-Path $PSScriptRoot 'helpers\New-AssessmentReport.ps1'
if (-not (Test-Path $helperReport)) {
    $helperReport = Join-Path $PSScriptRoot 'helpers/New-AssessmentReport.ps1'
}
. $helperReport

$resultArray  = [array]($allResults | Sort-Object Category, CheckId)
$reportOutput = New-AssessmentReport `
    -Results            $resultArray `
    -OutputPath         $resolvedOutput `
    -TenantId           $tenantId `
    -TenantName         $tenantId `
    -AssessmentDuration $durationStr

$riskColor = switch ($reportOutput.RiskLevel) {
    'LOW RISK'      { 'Green' }
    'MEDIUM RISK'   { 'Yellow' }
    'HIGH RISK'     { 'DarkYellow' }
    'CRITICAL RISK' { 'Red' }
    default         { 'White' }
}

Write-Host "`n[Assessment] Complete." -ForegroundColor Green
Write-Host "  Total findings : $($allResults.Count)"
Write-Host "  Duration       : $durationStr"
Write-Host "  Risk Score     : $($reportOutput.RiskScore) / 100 — $($reportOutput.RiskLevel)" -ForegroundColor $riskColor
Write-Host "  HTML Report    : $($reportOutput.HtmlPath)" -ForegroundColor Cyan
Write-Host "  JSON Export    : $($reportOutput.JsonPath)" -ForegroundColor Cyan

# Summary by status
$allResults | Group-Object Status | Sort-Object Name |
    ForEach-Object { Write-Host "  $($_.Name.PadRight(10)): $($_.Count)" }

return $allResults
