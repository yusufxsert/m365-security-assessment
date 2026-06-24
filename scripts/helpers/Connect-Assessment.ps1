#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Connects to Microsoft 365 services required for the security assessment.

.DESCRIPTION
    Establishes authenticated connections to Microsoft Graph using client credentials
    (app-only authentication). Optionally connects to Exchange Online and/or SharePoint
    Online when the corresponding switches are provided.

.PARAMETER TenantId
    The Entra ID tenant ID (GUID or .onmicrosoft.com domain).

.PARAMETER ClientId
    The application (client) ID of the app registration used for assessment.

.PARAMETER ClientSecret
    The client secret as a SecureString.

.PARAMETER Scopes
    Optional array of Graph permission scopes to request. Defaults to a minimal
    read-only set covering identity, policy, devices, and security.

.PARAMETER ConnectExchange
    If specified, also connects to Exchange Online (requires ExchangeOnlineManagement module).

.PARAMETER ConnectSharePoint
    If specified, also connects to SharePoint Online (requires PnP.PowerShell module).

.EXAMPLE
    $secret = ConvertTo-SecureString 'abc123' -AsPlainText -Force
    Connect-Assessment -TenantId 'contoso.onmicrosoft.com' -ClientId '...' -ClientSecret $secret

.EXAMPLE
    Connect-Assessment -TenantId $tid -ClientId $cid -ClientSecret $sec -ConnectExchange -Verbose
#>
function Connect-Assessment {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [SecureString]$ClientSecret,

        [string[]]$Scopes = @(),

        [switch]$ConnectExchange,

        [switch]$ConnectSharePoint
    )

    # --- Microsoft Graph ---
    try {
        Write-Verbose "Connecting to Microsoft Graph (TenantId: $TenantId, ClientId: $ClientId)"
        $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
        $graphParams = @{
            TenantId               = $TenantId
            ClientSecretCredential = $credential
            NoWelcome              = $true
            ErrorAction            = 'Stop'
        }
        Connect-MgGraph @graphParams
        Write-Verbose "Microsoft Graph connection established."
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        throw
    }

    # --- Exchange Online (optional) ---
    if ($ConnectExchange) {
        Write-Verbose "ConnectExchange specified — verifying ExchangeOnlineManagement module."
        if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
            Write-Error "ExchangeOnlineManagement module is not installed. Run: Install-Module ExchangeOnlineManagement"
            throw "Missing module: ExchangeOnlineManagement"
        }
        try {
            Write-Verbose "Connecting to Exchange Online (TenantId: $TenantId)"
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            # App-only auth for Exchange Online requires a certificate; client secret is not supported.
            # The caller must ensure the app has 'Exchange.ManageAsApp' permission and a cert configured.
            Connect-ExchangeOnline -AppId $ClientId -Organization $TenantId -ShowBanner:$false -ErrorAction Stop
            Write-Verbose "Exchange Online connection established."
        }
        catch {
            Write-Error "Failed to connect to Exchange Online: $_"
            throw
        }
    }

    # --- SharePoint Online (optional) ---
    if ($ConnectSharePoint) {
        Write-Verbose "ConnectSharePoint specified — verifying PnP.PowerShell module."
        if (-not (Get-Module -Name PnP.PowerShell -ListAvailable)) {
            Write-Error "PnP.PowerShell module is not installed. Run: Install-Module PnP.PowerShell"
            throw "Missing module: PnP.PowerShell"
        }
        try {
            Write-Verbose "Connecting to SharePoint Online (TenantId: $TenantId)"
            Import-Module PnP.PowerShell -ErrorAction Stop
            # App-only via client secret: Connect-PnPOnline requires the admin URL
            $adminUrl = "https://$(($TenantId -split '\.')[0])-admin.sharepoint.com"
            Write-Verbose "SharePoint Admin URL: $adminUrl"
            $plainSecret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
            Connect-PnPOnline -Url $adminUrl -ClientId $ClientId -ClientSecret $plainSecret -ErrorAction Stop
            Remove-Variable plainSecret -ErrorAction SilentlyContinue
            Write-Verbose "SharePoint Online connection established."
        }
        catch {
            Write-Error "Failed to connect to SharePoint Online: $_"
            throw
        }
    }

    return $true
}
