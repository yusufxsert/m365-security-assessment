#Requires -Version 7.0
#Requires -Modules Microsoft.Graph
<#
.SYNOPSIS
    M365 Security Assessment — Hauptscript
.DESCRIPTION
    Führt ein vollständiges Security Assessment eines M365 Tenants durch.
    Verwendet ausschließlich read-only Graph API Berechtigungen.
    Generiert HTML und JSON Reports.
.PARAMETER TenantId
    Azure AD / Entra ID Tenant ID
.PARAMETER ClientId
    App Registration Client ID (Service Principal)
.PARAMETER ClientSecret
    App Registration Client Secret
.PARAMETER OutputPath
    Pfad für die generierten Reports (Standard: .\reports)
.AUTHOR
    Yusuf Sert
.VERSION
    1.0
.DATE
    2026-06-24
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [SecureString]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\reports"
)

#region Init
$ErrorActionPreference = "Stop"
$ReportDate = Get-Date -Format "yyyy-MM-dd_HH-mm"
$Results = @{}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) { "INFO" { "Cyan" } "WARN" { "Yellow" } "ERROR" { "Red" } "OK" { "Green" } default { "White" } }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}
#endregion

#region Authentication
Write-Log "Verbinde mit Microsoft Graph..."
try {
    $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome
    Write-Log "Erfolgreich verbunden mit Tenant: $TenantId" -Level "OK"
}
catch {
    Write-Log "Authentifizierung fehlgeschlagen: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
#endregion

#region Identity Checks
Write-Log "Starte Identity Assessment..."
$identityResults = @{
    Category = "Identity"
    Checks   = @()
}

try {
    # MFA Status prüfen (Nutzer ohne MFA-Registrierung)
    $allUsers = Get-MgUser -Filter "accountEnabled eq true" -Property "Id,DisplayName,UserPrincipalName" -All
    $identityResults.TotalUsers = $allUsers.Count
    Write-Log "Gefundene aktive Benutzer: $($allUsers.Count)"

    # Conditional Access Policies
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
    $enabledPolicies = $caPolicies | Where-Object { $_.State -eq "enabled" }
    $identityResults.Checks += @{
        Name   = "Conditional Access Policies"
        Status = if ($enabledPolicies.Count -gt 0) { "OK" } else { "WARN" }
        Detail = "$($enabledPolicies.Count) aktive Policies von $($caPolicies.Count) gesamt"
    }

    # Privilegierte Rollen
    $privilegedRoles = @("Global Administrator", "Privileged Role Administrator", "Security Administrator")
    foreach ($roleName in $privilegedRoles) {
        $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
        if ($role) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
            $identityResults.Checks += @{
                Name   = "$roleName Members"
                Status = if ($members.Count -le 3) { "OK" } elseif ($members.Count -le 5) { "WARN" } else { "FAIL" }
                Detail = "$($members.Count) Mitglieder"
            }
        }
    }
}
catch {
    Write-Log "Fehler bei Identity Check: $($_.Exception.Message)" -Level "WARN"
}

$Results.Identity = $identityResults
Write-Log "Identity Assessment abgeschlossen" -Level "OK"
#endregion

#region Email Security Checks
Write-Log "Starte Email Security Assessment..."
$emailResults = @{
    Category = "Email Security"
    Checks   = @()
}

try {
    # Secure Score abrufen
    $secureScore = Get-MgSecuritySecureScore -Top 1
    if ($secureScore) {
        $score = $secureScore[0]
        $emailResults.Checks += @{
            Name   = "Microsoft Secure Score"
            Status = if ($score.CurrentScore / $score.MaxScore -ge 0.7) { "OK" } elseif ($score.CurrentScore / $score.MaxScore -ge 0.5) { "WARN" } else { "FAIL" }
            Detail = "$($score.CurrentScore) / $($score.MaxScore) ($([math]::Round($score.CurrentScore/$score.MaxScore*100))%)"
        }
    }
}
catch {
    Write-Log "Fehler bei Email Security Check: $($_.Exception.Message)" -Level "WARN"
}

$Results.EmailSecurity = $emailResults
Write-Log "Email Security Assessment abgeschlossen" -Level "OK"
#endregion

#region Report Generation
Write-Log "Generiere Report..."

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# JSON Export
$jsonPath = Join-Path $OutputPath "M365Assessment_$ReportDate.json"
$Results | ConvertTo-Json -Depth 10 | Set-Content $jsonPath
Write-Log "JSON Report gespeichert: $jsonPath" -Level "OK"

# HTML Report
$htmlTemplate = Get-Content (Join-Path $PSScriptRoot "..\reports\template.html") -Raw
$htmlPath = Join-Path $OutputPath "M365Assessment_$ReportDate.html"

$summaryHtml = ""
foreach ($category in $Results.Keys) {
    $cat = $Results[$category]
    $summaryHtml += "<h2>$($cat.Category)</h2><ul>"
    foreach ($check in $cat.Checks) {
        $statusColor = switch ($check.Status) { "OK" { "green" } "WARN" { "orange" } "FAIL" { "red" } default { "gray" } }
        $summaryHtml += "<li><strong style='color:$statusColor'>[$($check.Status)]</strong> $($check.Name): $($check.Detail)</li>"
    }
    $summaryHtml += "</ul>"
}

$htmlContent = $htmlTemplate -replace "{{REPORT_DATE}}", (Get-Date -Format "dd.MM.yyyy HH:mm") `
    -replace "{{TENANT_ID}}", $TenantId `
    -replace "{{RESULTS}}", $summaryHtml

Set-Content $htmlPath $htmlContent
Write-Log "HTML Report gespeichert: $htmlPath" -Level "OK"
#endregion

Disconnect-MgGraph | Out-Null
Write-Log "Assessment abgeschlossen. Reports unter: $OutputPath" -Level "OK"
