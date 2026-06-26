#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Checks whether legacy authentication protocols are blocked and in active use.
.DESCRIPTION
    Evaluates Conditional Access policies blocking legacy auth, Exchange Online
    authentication policies (if EXO connected), active legacy auth sign-ins
    in the last 30 days, and per-mailbox legacy auth overrides.
    Checks: LEG-001 through LEG-004.
.NOTES
    Required Permissions:
        Policy.Read.All
        AuditLog.Read.All
    License: E3 minimum; sign-in logs require E3+
    Exchange Online: ExchangeOnlineManagement module required for LEG-002/LEG-004
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/Authentication/Test-LegacyAuth.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-LegacyAuth {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # LEG-001: CA policy blocking legacy authentication
    try {
        $caPolicies        = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        $legacyClientTypes = @('exchangeActiveSync', 'other')

        $blockingPolicies = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and
            ($_.Conditions.ClientAppTypes | Where-Object { $_ -in $legacyClientTypes }) -and
            $_.GrantControls.BuiltInControls -contains 'block'
        }

        $reportOnlyPolicies = $caPolicies | Where-Object {
            $_.State -eq 'enabledForReportingButNotEnforced' -and
            ($_.Conditions.ClientAppTypes | Where-Object { $_ -in $legacyClientTypes })
        }

        $secDefaults        = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
            -ErrorAction SilentlyContinue
        $secDefaultsEnabled = $secDefaults.isEnabled -eq $true

        if ($blockingPolicies.Count -gt 0) {
            $policyNames = ($blockingPolicies | Select-Object -ExpandProperty DisplayName) -join ', '
            $results.Add((New-CheckResult `
                -CheckId        'LEG-001' `
                -Category       'Authentication' `
                -Name           'Legacy Auth Blocked by CA' `
                -Status         'PASS' `
                -Detail         "$($blockingPolicies.Count) enabled CA policy/policies block legacy authentication: $policyNames" `
                -Recommendation 'Keep these policies active. Monitor for legacy auth sign-in attempts via LEG-003 to detect devices that need migration.' `
                -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
                -CISControl     'CIS M365 1.2.3' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        elseif ($secDefaultsEnabled) {
            $results.Add((New-CheckResult `
                -CheckId        'LEG-001' `
                -Category       'Authentication' `
                -Name           'Legacy Auth Blocked by Security Defaults' `
                -Status         'PASS' `
                -Detail         'No CA policy blocking legacy auth found, but Security Defaults is ENABLED, which blocks legacy auth protocols.' `
                -Recommendation 'When migrating from Security Defaults to Conditional Access, ensure a CA policy explicitly blocking legacy auth is in place before disabling Security Defaults.' `
                -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
                -CISControl     'CIS M365 1.2.3' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        elseif ($reportOnlyPolicies.Count -gt 0) {
            $policyNames = ($reportOnlyPolicies | Select-Object -ExpandProperty DisplayName) -join ', '
            $results.Add((New-CheckResult `
                -CheckId        'LEG-001' `
                -Category       'Authentication' `
                -Name           'Legacy Auth Block in Report-Only Mode' `
                -Status         'HIGH' `
                -Detail         "Legacy auth block policy exists but is in report-only mode (not enforced): $policyNames. Security Defaults: $secDefaultsEnabled." `
                -Recommendation 'Transition the report-only legacy auth block policy to enabled. Review the report-only sign-in logs to identify affected clients before enabling.' `
                -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
                -CISControl     'CIS M365 1.2.3' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($reportOnlyPolicies.DisplayName)))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId        'LEG-001' `
                -Category       'Authentication' `
                -Name           'Legacy Auth Not Blocked' `
                -Status         'CRITICAL' `
                -Detail         'No enabled CA policy blocks legacy authentication AND Security Defaults is disabled. Legacy auth bypasses MFA entirely.' `
                -Recommendation 'Create an enabled CA policy: Target All Users, Client Apps = Exchange Active Sync + Other, Grant = Block. Test in report-only mode first.' `
                -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
                -CISControl     'CIS M365 1.2.3' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'LEG-001' `
            -Category       'Authentication' `
            -Name           'Legacy Auth CA Policy' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # LEG-002: Basic auth on Exchange Online protocols (requires EXO module)
    try {
        $exoConnected = [bool](Get-Command Get-AuthenticationPolicy -ErrorAction SilentlyContinue)

        if (-not $exoConnected) {
            $results.Add((New-CheckResult `
                -CheckId        'LEG-002' `
                -Category       'Authentication' `
                -Name           'Exchange Online Basic Auth Policies' `
                -Status         'INFO' `
                -Detail         'Exchange Online PowerShell module (ExchangeOnlineManagement) is not connected. This check requires an active EXO session.' `
                -Recommendation 'Connect to Exchange Online using Connect-ExchangeOnline and re-run this check to evaluate Get-AuthenticationPolicy for BasicAuth status.' `
                -Reference      'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        else {
            $authPolicies     = Get-AuthenticationPolicy -ErrorAction Stop
            $basicAuthEnabled = $authPolicies | Where-Object {
                $_.AllowBasicAuthActiveSync      -eq $true -or
                $_.AllowBasicAuthImap            -eq $true -or
                $_.AllowBasicAuthPop             -eq $true -or
                $_.AllowBasicAuthSmtpAuth        -eq $true -or
                $_.AllowBasicAuthWebServices     -eq $true -or
                $_.AllowBasicAuthRpc             -eq $true -or
                $_.AllowBasicAuthOfflineAddressBook -eq $true -or
                $_.AllowBasicAuthPowershell      -eq $true -or
                $_.AllowBasicAuthMapi            -eq $true -or
                $_.AllowBasicAuthOutlookService  -eq $true
            }

            $results.Add((New-CheckResult `
                -CheckId        'LEG-002' `
                -Category       'Authentication' `
                -Name           'Exchange Online Basic Auth' `
                -Status         (if ($basicAuthEnabled.Count -gt 0) { 'CRITICAL' } else { 'PASS' }) `
                -Detail         "Authentication policies with Basic Auth enabled: $($basicAuthEnabled.Count) of $($authPolicies.Count). Basic auth in Exchange Online bypasses MFA." `
                -Recommendation 'Disable all Basic Auth protocols in Exchange Online authentication policies. Migrate clients to modern authentication (OAuth 2.0).' `
                -Reference      'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' `
                -CISControl     'CIS M365 1.2.3' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($basicAuthEnabled.Name)))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'LEG-002' `
            -Category       'Authentication' `
            -Name           'Exchange Online Basic Auth' `
            -Status         'INFO' `
            -Detail         "Check failed. Error: $_" `
            -Recommendation 'Verify Exchange Online PowerShell connection and permissions.' `
            -Reference      'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # LEG-003: Active legacy auth sign-ins in last 30 days
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $legacyAppTypes = @('exchangeActiveSync','imap','mapi','other','pop3','smtp')
        $filterParts    = $legacyAppTypes | ForEach-Object { "clientAppUsed eq '$_'" }
        $filter         = "($($filterParts -join ' or ')) and createdDateTime ge $thirtyDaysAgo"

        $legacySignIns = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=999&`$select=userPrincipalName,clientAppUsed,createdDateTime,ipAddress,status" `
            -ErrorAction Stop

        $signInList   = $legacySignIns.value
        $legacyCount  = if ($signInList) { $signInList.Count } else { 0 }
        $uniqueUsers  = if ($signInList) { ($signInList | Select-Object -ExpandProperty userPrincipalName | Sort-Object -Unique).Count } else { 0 }
        $sourceIps    = if ($signInList) { ($signInList | Select-Object -ExpandProperty ipAddress | Sort-Object -Unique | Select-Object -First 10) -join ', ' } else { 'N/A' }

        $results.Add((New-CheckResult `
            -CheckId        'LEG-003' `
            -Category       'Authentication' `
            -Name           'Active Legacy Auth Sign-Ins (Last 30 Days)' `
            -Status         (if ($legacyCount -eq 0) { 'PASS' } else { 'HIGH' }) `
            -Detail         "$legacyCount legacy auth sign-in event(s) in last 30 days from $uniqueUsers unique user(s). Sample source IPs: $sourceIps" `
            -Recommendation 'Identify clients still using legacy auth and migrate them to modern auth. Common causes: old Outlook versions, mail clients, automation scripts, printers. Once all migrated, enable LEG-001 CA block.' `
            -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
            -CISControl     'CIS M365 1.2.3' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'LEG-003' `
            -Category       'Authentication' `
            -Name           'Legacy Auth Sign-In Activity' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or API error. Required: AuditLog.Read.All. Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All to the service principal.' `
            -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # LEG-004: Per-mailbox legacy auth override (requires EXO module)
    try {
        $exoConnected = [bool](Get-Command Get-CASMailbox -ErrorAction SilentlyContinue)

        if (-not $exoConnected) {
            $results.Add((New-CheckResult `
                -CheckId        'LEG-004' `
                -Category       'Authentication' `
                -Name           'Per-Mailbox Legacy Auth Overrides' `
                -Status         'INFO' `
                -Detail         'Exchange Online PowerShell module is not connected. This check requires Get-CASMailbox.' `
                -Recommendation 'Connect to Exchange Online using Connect-ExchangeOnline and re-run this check to evaluate per-mailbox legacy auth settings.' `
                -Reference      'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        else {
            $mailboxes       = Get-CASMailbox -ResultSize Unlimited -ErrorAction Stop
            $legacyMailboxes = $mailboxes | Where-Object {
                $_.ActiveSyncEnabled -eq $true -or
                $_.ImapEnabled       -eq $true -or
                $_.PopEnabled        -eq $true -or
                $_.MAPIEnabled       -eq $true
            }

            $legacyCount = $legacyMailboxes.Count
            $sampleUpns  = ($legacyMailboxes | Select-Object -First 10 -ExpandProperty PrimarySmtpAddress) -join ', '

            $results.Add((New-CheckResult `
                -CheckId        'LEG-004' `
                -Category       'Authentication' `
                -Name           'Per-Mailbox Legacy Auth Overrides' `
                -Status         (if ($legacyCount -eq 0) { 'PASS' } else { 'MEDIUM' }) `
                -Detail         "$legacyCount mailbox(es) have legacy protocol access enabled (ActiveSync/IMAP/POP/MAPI). Sample: $sampleUpns" `
                -Recommendation 'Disable legacy protocols per mailbox where not required. Apply an authentication policy that disables BasicAuth to all mailboxes.' `
                -Reference      'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($legacyMailboxes | Select-Object -First 20 -ExpandProperty PrimarySmtpAddress)))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'LEG-004' `
            -Category       'Authentication' `
            -Name           'Per-Mailbox Legacy Auth Overrides' `
            -Status         'INFO' `
            -Detail         "Check failed. Error: $_" `
            -Recommendation 'Verify Exchange Online PowerShell connection.' `
            -Reference      'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
