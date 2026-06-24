#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Orchestrates a read-only Microsoft 365 security assessment.

.DESCRIPTION
    Dot-sources all helper scripts, connects to Microsoft 365 services, discovers
    and runs module scripts under scripts/modules/, collects results, prints a
    colored console summary, and generates HTML and JSON reports.

    Module scripts are expected to live in scripts/modules/<Category>/ and export
    a single function named Invoke-<Category><FileName> or similar. Each module
    function must return PSCustomObject[] produced by New-CheckResult.

    The framework never writes to Microsoft 365 — all operations are read-only.

.PARAMETER TenantId
    Entra ID tenant ID (GUID or .onmicrosoft.com domain). Mandatory.

.PARAMETER ClientId
    Application (client) ID of the assessment app registration. Mandatory.

.PARAMETER ClientSecret
    Client secret of the app registration as a SecureString. Mandatory.

.PARAMETER OutputPath
    Directory for HTML and JSON report output. Default: ./reports/

.PARAMETER Modules
    Optional filter: only run modules whose parent folder name matches one of
    these strings (case-insensitive). Example: @('Identity','Defender').
    If empty or not specified, all discovered modules run.

.PARAMETER ConnectExchange
    Connect to Exchange Online in addition to Microsoft Graph.

.PARAMETER ConnectSharePoint
    Connect to SharePoint Online in addition to Microsoft Graph.

.PARAMETER Parallel
    Run module scripts in parallel using ForEach-Object -Parallel with
    ThrottleLimit 4. Disabled by default for simpler error reporting.

.EXAMPLE
    $secret = ConvertTo-SecureString $env:CLIENT_SECRET -AsPlainText -Force
    .\Start-M365Assessment.ps1 -TenantId $env:TENANT_ID -ClientId $env:CLIENT_ID -ClientSecret $secret

.EXAMPLE
    .\Start-M365Assessment.ps1 -TenantId $tid -ClientId $cid -ClientSecret $sec `
        -Modules @('Identity','Defender') -OutputPath C:\Reports -Verbose

.EXAMPLE
    .\Start-M365Assessment.ps1 -TenantId $tid -ClientId $cid -ClientSecret $sec -Parallel
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [Parameter(Mandatory)]
    [SecureString]$ClientSecret,

    [string]$OutputPath = './reports/',

    [string[]]$Modules = @(),

    [switch]$ConnectExchange,

    [switch]$ConnectSharePoint,

    [switch]$Parallel
)

$ErrorActionPreference = 'Stop'
$startTime = Get-Date

# ---- Helper: New-CheckResult (defined here so helpers can reference it too) ----
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
        [string[]]$AffectedObjects = @()
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
        Timestamp       = (Get-Date -Format 'o')
    }
}

# ---- Validate parameters -------------------------------------------------------
if (-not $TenantId  -or $TenantId.Trim()  -eq '') { throw "TenantId must not be empty." }
if (-not $ClientId  -or $ClientId.Trim()  -eq '') { throw "ClientId must not be empty." }

# ---- Ensure output directory exists -------------------------------------------
$resolvedOutput = $OutputPath
if (-not [System.IO.Path]::IsPathRooted($resolvedOutput)) {
    $resolvedOutput = Join-Path $PSScriptRoot $resolvedOutput
}
if (-not (Test-Path $resolvedOutput)) {
    New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
}

$logFile = Join-Path $resolvedOutput "assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# ---- Dot-source helpers --------------------------------------------------------
$helperDir = Join-Path $PSScriptRoot 'helpers'
if (-not (Test-Path $helperDir)) {
    throw "Helpers directory not found at: $helperDir"
}

$helperScripts = Get-ChildItem -Path $helperDir -Filter '*.ps1' -File | Sort-Object Name
foreach ($helper in $helperScripts) {
    Write-Verbose "Loading helper: $($helper.Name)"
    . $helper.FullName
}

Write-AssessmentLog -Message "M365 Security Assessment starting." -Level INFO -LogPath $logFile
Write-AssessmentLog -Message "TenantId: $TenantId | OutputPath: $resolvedOutput" -Level INFO -LogPath $logFile

# ---- Connect -------------------------------------------------------------------
$connectParams = @{
    TenantId     = $TenantId
    ClientId     = $ClientId
    ClientSecret = $ClientSecret
}
if ($ConnectExchange)  { $connectParams['ConnectExchange']  = $true }
if ($ConnectSharePoint){ $connectParams['ConnectSharePoint'] = $true }

Write-AssessmentLog -Message "Connecting to Microsoft 365..." -Level INFO -LogPath $logFile

try {
    Connect-Assessment @connectParams
    Write-AssessmentLog -Message "Connected successfully." -Level SUCCESS -LogPath $logFile
}
catch {
    Write-AssessmentLog -Message "Connection failed: $_" -Level ERROR -LogPath $logFile
    throw
}

# ---- Discover module scripts ---------------------------------------------------
$moduleRoot = Join-Path $PSScriptRoot 'modules'
if (-not (Test-Path $moduleRoot)) {
    Write-AssessmentLog -Message "No modules directory found at $moduleRoot — nothing to run." -Level WARN -LogPath $logFile
    return
}

$allModuleFiles = Get-ChildItem -Path $moduleRoot -Filter '*.ps1' -Recurse -File | Sort-Object FullName

if ($Modules -and $Modules.Count -gt 0) {
    $allModuleFiles = $allModuleFiles | Where-Object {
        $parentDir = $_.Directory.Name
        $Modules | Where-Object { $parentDir -like $_ }
    }
    Write-AssessmentLog -Message "Module filter active: $($Modules -join ', ') — $($allModuleFiles.Count) script(s) matched." -Level INFO -LogPath $logFile
}
else {
    Write-AssessmentLog -Message "Running all $($allModuleFiles.Count) module script(s)." -Level INFO -LogPath $logFile
}

if ($allModuleFiles.Count -eq 0) {
    Write-AssessmentLog -Message "No module scripts found. Exiting." -Level WARN -LogPath $logFile
    return
}

# ---- Run modules ---------------------------------------------------------------
$AllResults   = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$moduleErrors = [System.Collections.Concurrent.ConcurrentBag[string]]::new()
$totalModules = $allModuleFiles.Count
$moduleIndex  = 0

$statusColors = @{
    CRITICAL = 'Red'
    HIGH     = 'DarkYellow'
    MEDIUM   = 'Yellow'
    LOW      = 'Cyan'
    INFO     = 'Gray'
    PASS     = 'Green'
}

function Invoke-ModuleScript {
    param([System.IO.FileInfo]$ModuleFile)

    $funcResults = @()
    $elapsed     = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        # Each module file is dot-sourced then its exported function is called.
        # Convention: module function name is derived from the file name.
        # e.g. Test-EntraMFARegistration.ps1 exports Test-EntraMFARegistration
        . $ModuleFile.FullName

        $funcName = [System.IO.Path]::GetFileNameWithoutExtension($ModuleFile.Name)
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            $funcResults = & $funcName
        }
        else {
            # Fallback: look for any function defined in the file that starts with Test- or Invoke-
            $defined = Get-Command -CommandType Function | Where-Object {
                $_.Name -match '^(Test|Invoke)-' -and $_.ScriptBlock.File -eq $ModuleFile.FullName
            }
            if ($defined) {
                $funcResults = & $defined[0].Name
            }
            else {
                Write-Warning "No callable function found in $($ModuleFile.Name)"
            }
        }
    }
    catch {
        $funcResults = @(New-CheckResult `
            -CheckId    "ERR-$([System.IO.Path]::GetFileNameWithoutExtension($ModuleFile.Name).ToUpper() -replace '[^A-Z0-9]','')" `
            -Category   $ModuleFile.Directory.Name `
            -Name       "Module execution error: $($ModuleFile.Name)" `
            -Status     'CRITICAL' `
            -Detail     "Module threw an exception: $_" `
            -Recommendation 'Review module script and verify required Graph permissions are granted.' `
            -Reference  '' `
            -CISControl '' `
            -SC300Domain '' `
            -LicenseRequired 'None'
        )
    }

    $elapsed.Stop()
    return [PSCustomObject]@{
        ModuleName = $ModuleFile.Name
        Category   = $ModuleFile.Directory.Name
        Results    = $funcResults
        Duration   = $elapsed.Elapsed
        Count      = if ($funcResults) { $funcResults.Count } else { 0 }
    }
}

Write-AssessmentLog -Message "Starting module execution (Parallel: $($Parallel.IsPresent))..." -Level INFO -LogPath $logFile

try {
    if ($Parallel) {
        # -Parallel requires variables to be passed via $using:
        $moduleFileList = $allModuleFiles | Select-Object FullName, Name, @{N='DirName';E={$_.Directory.Name}}

        $parallelResults = $moduleFileList | ForEach-Object -Parallel {
            $mf         = $_
            $logFilePath = $using:logFile

            # Re-define New-CheckResult in the parallel runspace
            function New-CheckResult {
                param(
                    [string]$CheckId,[string]$Category,[string]$Name,
                    [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO','PASS')][string]$Status,
                    [string]$Detail,[string]$Recommendation,[string]$Reference,
                    [string]$CISControl,[string]$SC300Domain,
                    [ValidateSet('E3','E5','Both','None')][string]$LicenseRequired = 'None',
                    [string[]]$AffectedObjects = @()
                )
                [PSCustomObject]@{
                    CheckId=$CheckId; Category=$Category; Name=$Name; Status=$Status
                    Detail=$Detail; Recommendation=$Recommendation; Reference=$Reference
                    CISControl=$CISControl; SC300Domain=$SC300Domain
                    LicenseRequired=$LicenseRequired; AffectedObjects=$AffectedObjects
                    Timestamp=(Get-Date -Format 'o')
                }
            }

            $funcResults = @()
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                . $mf.FullName
                $funcName = [System.IO.Path]::GetFileNameWithoutExtension($mf.Name)
                if (Get-Command $funcName -ErrorAction SilentlyContinue) {
                    $funcResults = & $funcName
                }
            }
            catch {
                $funcResults = @(New-CheckResult `
                    -CheckId    "ERR-$($mf.Name.ToUpper() -replace '[^A-Z0-9]','')" `
                    -Category   $mf.DirName `
                    -Name       "Module error: $($mf.Name)" `
                    -Status     'CRITICAL' `
                    -Detail     "Exception: $_" `
                    -Recommendation 'Review module and Graph permissions.' `
                    -LicenseRequired 'None'
                )
            }
            $sw.Stop()
            [PSCustomObject]@{
                ModuleName = $mf.Name
                Category   = $mf.DirName
                Results    = $funcResults
                Duration   = $sw.Elapsed
                Count      = if ($funcResults) { $funcResults.Count } else { 0 }
            }
        } -ThrottleLimit 4

        foreach ($pr in $parallelResults) {
            if ($pr.Results) { foreach ($r in $pr.Results) { $AllResults.Add($r) } }
            $icon = if (($pr.Results | Where-Object Status -in 'CRITICAL','HIGH').Count -gt 0) { 'x' } else { 'v' }
            $topStatus = ($pr.Results | Sort-Object { @('CRITICAL','HIGH','MEDIUM','LOW','INFO','PASS').IndexOf($_.Status) } | Select-Object -First 1).Status
            $color = $statusColors[$topStatus] ?? 'White'
            Write-Host ("[{0:hh\:mm\:ss}] {1} {2,-8} {3} > {4} ({5} checks)" -f
                (Get-Date - $startTime), $icon, $topStatus, $pr.Category, $pr.ModuleName, $pr.Count) -ForegroundColor $color
            Write-AssessmentLog -Message "$($pr.Category) > $($pr.ModuleName): $($pr.Count) results in $($pr.Duration.TotalSeconds.ToString('F2'))s" -Level INFO -LogPath $logFile
        }

    }
    else {
        # Sequential with Write-Progress
        foreach ($moduleFile in $allModuleFiles) {
            $moduleIndex++
            $category  = $moduleFile.Directory.Name
            $modName   = $moduleFile.Name

            Write-Progress -Activity 'M365 Security Assessment' `
                -Status "[$moduleIndex/$totalModules] $category > $modName" `
                -PercentComplete (($moduleIndex / $totalModules) * 100)

            $result = Invoke-ModuleScript -ModuleFile $moduleFile

            if ($result.Results) {
                foreach ($r in $result.Results) { $AllResults.Add($r) }
            }

            $topStatus = ($result.Results | Sort-Object { @('CRITICAL','HIGH','MEDIUM','LOW','INFO','PASS').IndexOf($_.Status) } | Select-Object -First 1).Status
            if (-not $topStatus) { $topStatus = 'INFO' }
            $color = $statusColors[$topStatus] ?? 'White'
            $icon  = if ($topStatus -in 'CRITICAL','HIGH') { [char]0x2717 } else { [char]0x2713 }

            Write-Host ("[{0:hh\:mm\:ss}] {1} {2,-8} {3} > {4} ({5} checks)" -f
                (Get-Date - $startTime), $icon, $topStatus, $category, $modName, $result.Count) -ForegroundColor $color

            Write-AssessmentLog -Message "$category > $modName : $($result.Count) results in $($result.Duration.TotalSeconds.ToString('F2'))s" -Level INFO -LogPath $logFile
        }
        Write-Progress -Activity 'M365 Security Assessment' -Completed
    }
}
finally {
    # Always disconnect, even on error
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-AssessmentLog -Message "Disconnected from Microsoft Graph." -Level INFO -LogPath $logFile
    }
    catch {
        Write-AssessmentLog -Message "Disconnect-MgGraph warning: $_" -Level WARN -LogPath $logFile
    }
}

# ---- Collect and summarise results ---------------------------------------------
$resultArray = [PSCustomObject[]]@($AllResults)
$duration    = (Get-Date) - $startTime
$durationStr = $duration.ToString('hh\:mm\:ss')

Write-AssessmentLog -Message "Assessment complete. $($resultArray.Count) total results in $durationStr." -Level SUCCESS -LogPath $logFile

# Console summary table
$summaryData = $resultArray | Group-Object Status | Select-Object Name, Count | Sort-Object Name
Write-Host "`n===== Assessment Summary =====" -ForegroundColor Cyan
$summaryData | Format-Table -AutoSize | Out-String | Write-Host

$critCount = ($resultArray | Where-Object Status -eq 'CRITICAL').Count
$highCount = ($resultArray | Where-Object Status -eq 'HIGH').Count
$medCount  = ($resultArray | Where-Object Status -eq 'MEDIUM').Count
$lowCount  = ($resultArray | Where-Object Status -eq 'LOW').Count
$infoCount = ($resultArray | Where-Object Status -eq 'INFO').Count
$passCount = ($resultArray | Where-Object Status -eq 'PASS').Count

Write-Host ("CRITICAL: {0,-4} HIGH: {1,-4} MEDIUM: {2,-4} LOW: {3,-4} INFO: {4,-4} PASS: {5}" -f
    $critCount, $highCount, $medCount, $lowCount, $infoCount, $passCount) -ForegroundColor White

# ---- Generate report -----------------------------------------------------------
if ($resultArray.Count -gt 0) {
    Write-AssessmentLog -Message "Generating reports..." -Level INFO -LogPath $logFile

    $tenantName = $TenantId   # caller can pass a friendly name via env if desired
    $reportOutput = New-AssessmentReport `
        -Results            $resultArray `
        -OutputPath         $resolvedOutput `
        -TenantId           $TenantId `
        -TenantName         $tenantName `
        -AssessmentDuration $durationStr

    Write-AssessmentLog -Message "HTML: $($reportOutput.HtmlPath)" -Level SUCCESS -LogPath $logFile
    Write-AssessmentLog -Message "JSON: $($reportOutput.JsonPath)" -Level SUCCESS -LogPath $logFile
    Write-AssessmentLog -Message "Risk Score: $($reportOutput.RiskScore) — $($reportOutput.RiskLevel)" -Level INFO -LogPath $logFile

    Write-Host "`nRisk Score : $($reportOutput.RiskScore) / 100 — $($reportOutput.RiskLevel)" -ForegroundColor $(
        switch ($reportOutput.RiskLevel) {
            'LOW RISK'      { 'Green'  }
            'MEDIUM RISK'   { 'Yellow' }
            'HIGH RISK'     { 'DarkYellow' }
            'CRITICAL RISK' { 'Red'    }
        }
    )
    Write-Host "HTML Report: $($reportOutput.HtmlPath)" -ForegroundColor Cyan
    Write-Host "JSON Export: $($reportOutput.JsonPath)" -ForegroundColor Cyan
    Write-Host "Log File   : $logFile" -ForegroundColor Gray
}
else {
    Write-AssessmentLog -Message "No results collected — no report generated." -Level WARN -LogPath $logFile
    Write-Host "No results collected. Verify module scripts exist in $moduleRoot and return New-CheckResult objects." -ForegroundColor Yellow
}

Write-AssessmentLog -Message "Assessment finished in $durationStr." -Level SUCCESS -LogPath $logFile
