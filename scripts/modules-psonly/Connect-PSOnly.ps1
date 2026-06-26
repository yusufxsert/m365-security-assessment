#Requires -Version 7.0

<#
.SYNOPSIS
    Establishes interactive connections for the PowerShell-only assessment.

.DESCRIPTION
    Connect-PSOnly handles all module connections required for the PS-only
    assessment variant. It uses DELEGATED permissions (interactive browser login
    or device code) — no App Registration or service principal required.

    Required modules (install once):
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
        Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
        Install-Module Microsoft.Graph.Users -Scope CurrentUser
        Install-Module Microsoft.Graph.Groups -Scope CurrentUser
        Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
        Install-Module Microsoft.Graph.DeviceManagement -Scope CurrentUser
        Install-Module Microsoft.Graph.Applications -Scope CurrentUser
        Install-Module Microsoft.Graph.Reports -Scope CurrentUser
        Install-Module ExchangeOnlineManagement -Scope CurrentUser

.PARAMETER UPN
    The user principal name used for Exchange Online and IPPS connections.
    Example: admin@contoso.onmicrosoft.com

.PARAMETER UseDeviceCode
    Use device code flow instead of interactive browser login.
    Required for headless environments (SSH sessions, servers without GUI).

.PARAMETER ConnectExchange
    Also connect to Exchange Online. Required for EmailSecurity and Authentication checks.

.PARAMETER ConnectIPPS
    Also connect to Security & Compliance Center (IPPS).
    Required for DataProtection (DLP, Sensitivity Labels) and Monitoring/AuditLog checks.

.PARAMETER GraphScopes
    Additional Microsoft Graph permission scopes to request beyond the defaults.

.EXAMPLE
    # Minimal: Graph only
    . .\Connect-PSOnly.ps1
    Connect-PSOnly -UPN admin@contoso.com

    # Full: Graph + EXO + IPPS
    Connect-PSOnly -UPN admin@contoso.com -ConnectExchange -ConnectIPPS

    # Headless (no browser)
    Connect-PSOnly -UPN admin@contoso.com -UseDeviceCode -ConnectExchange

.NOTES
    This script replaces the App Registration + certificate auth used in the main
    Start-M365Assessment.ps1. All permissions are delegated — the user running
    the script needs the relevant admin roles in the tenant.

    Minimum recommended roles:
        - Security Reader or Global Reader (read-only assessment)
        - Exchange Administrator (for EXO checks)
        - Compliance Administrator (for IPPS/Purview checks)
#>

function Connect-PSOnly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UPN,

        [switch]$UseDeviceCode,
        [switch]$ConnectExchange,
        [switch]$ConnectIPPS,

        [string[]]$GraphScopes = @()
    )

    # Default Graph scopes covering all PS-only assessment checks
    $defaultScopes = @(
        'User.Read.All'
        'Group.Read.All'
        'Directory.Read.All'
        'Policy.Read.All'
        'RoleManagement.Read.All'
        'AuditLog.Read.All'
        'Reports.Read.All'
        'Domain.Read.All'
        'Application.Read.All'
        'UserAuthenticationMethod.Read.All'
        'IdentityRiskEvent.Read.All'
        'IdentityRiskyUser.Read.All'
        'EntitlementManagement.Read.All'
        'AccessReview.Read.All'
        'Agreement.Read.All'
        'DeviceManagementConfiguration.Read.All'
        'DeviceManagementManagedDevices.Read.All'
        'InformationProtectionPolicy.Read'
        'SecurityEvents.Read.All'
    )

    $allScopes = ($defaultScopes + $GraphScopes) | Sort-Object -Unique

    # ---- Microsoft Graph (interactive / device code) -------------------------
    Write-Host '[Connect-PSOnly] Connecting to Microsoft Graph...' -ForegroundColor Cyan

    $mgParams = @{ Scopes = $allScopes }
    if ($UseDeviceCode) { $mgParams['UseDeviceAuthentication'] = $true }

    try {
        Connect-MgGraph @mgParams -NoWelcome -ErrorAction Stop
        $ctx = Get-MgContext
        Write-Host "[Connect-PSOnly] Graph connected. Tenant: $($ctx.TenantId) | Account: $($ctx.Account)" -ForegroundColor Green
    }
    catch {
        throw "Graph connection failed: $_"
    }

    # ---- Exchange Online -------------------------------------------------------
    if ($ConnectExchange) {
        Write-Host '[Connect-PSOnly] Connecting to Exchange Online...' -ForegroundColor Cyan
        try {
            Connect-ExchangeOnline -UserPrincipalName $UPN -ShowBanner:$false -ErrorAction Stop
            Write-Host '[Connect-PSOnly] Exchange Online connected.' -ForegroundColor Green
        }
        catch {
            Write-Warning "Exchange Online connection failed: $_. EXO-dependent checks will be skipped."
        }
    }

    # ---- Security & Compliance (IPPS) ----------------------------------------
    if ($ConnectIPPS) {
        Write-Host '[Connect-PSOnly] Connecting to Security & Compliance Center (IPPS)...' -ForegroundColor Cyan
        try {
            Connect-IPPSSession -UserPrincipalName $UPN -ShowBanner:$false -ErrorAction Stop
            Write-Host '[Connect-PSOnly] IPPS connected.' -ForegroundColor Green
        }
        catch {
            Write-Warning "IPPS connection failed: $_. Purview/Compliance checks will be skipped."
        }
    }
}
