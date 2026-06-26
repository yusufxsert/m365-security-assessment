#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Reports, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Checks MFA registration coverage and enforcement quality across the tenant.
.DESCRIPTION
    Evaluates MFA registration rate for all users, MFA coverage for admins,
    enforcement method (CA vs per-user vs Security Defaults), passwordless
    adoption, and auth method resilience (average methods per user).
    Checks: MFA-001 through MFA-005.
.NOTES
    Required Permissions:
        Reports.Read.All
        UserAuthenticationMethod.Read.All
        Policy.Read.All
        RoleManagement.Read.Directory
        Directory.Read.All
    License: E3 minimum; per-user MFA status requires Reports.Read.All
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/Authentication/Test-MFACoverage.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-MFACoverage {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Fetch credential registration details once — used by MFA-001, MFA-004, MFA-005
    $regDetails = $null
    try {
        $regDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'MFA-000' `
            -Category       'Authentication' `
            -Name           'Registration Report Access' `
            -Status         'INFO' `
            -Detail         "Could not retrieve authentication method registration details. MFA-001, MFA-004, MFA-005 skipped. Required: Reports.Read.All. Error: $_" `
            -Recommendation 'Grant Reports.Read.All to the service principal.' `
            -Reference      'https://learn.microsoft.com/graph/api/reportroot-list-credentialuserregistrationdetails' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # MFA-001: MFA registration rate (all users)
    if ($regDetails) {
        try {
            $totalUsers    = $regDetails.Count
            $mfaRegistered = ($regDetails | Where-Object { $_.IsMfaRegistered -eq $true }).Count
            $pct           = if ($totalUsers -gt 0) { [math]::Round(($mfaRegistered / $totalUsers) * 100, 1) } else { 0 }

            $checkStatus = if ($pct -ge 95) { 'PASS' } elseif ($pct -ge 80) { 'MEDIUM' } elseif ($pct -ge 50) { 'HIGH' } else { 'CRITICAL' }

            $results.Add((New-CheckResult `
                -CheckId        'MFA-001' `
                -Category       'Authentication' `
                -Name           'MFA Registration Rate' `
                -Status         $checkStatus `
                -Detail         "$mfaRegistered of $totalUsers users have MFA registered ($pct%). Target: 95%+." `
                -Recommendation 'Enable the authentication methods registration campaign. Enforce MFA registration via Conditional Access (require registration as grant control). Target 100%.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
                -CISControl     'CIS M365 1.1.2' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId        'MFA-001' `
                -Category       'Authentication' `
                -Name           'MFA Registration Rate' `
                -Status         'INFO' `
                -Detail         "Failed to process registration details: $_" `
                -Recommendation '' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }

    # MFA-002: Admins without MFA
    try {
        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $privilegedRoleNames = @(
            'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
            'Exchange Administrator', 'SharePoint Administrator', 'Teams Administrator',
            'Compliance Administrator', 'Application Administrator',
            'Cloud Application Administrator', 'Authentication Administrator',
            'Privileged Authentication Administrator', 'User Administrator',
            'Hybrid Identity Administrator'
        )
        $privilegedRoles = $allRoles | Where-Object { $_.DisplayName -in $privilegedRoleNames }

        $adminIds   = [System.Collections.Generic.HashSet[string]]::new()
        $adminUpnMap = @{}

        foreach ($role in $privilegedRoles) {
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
                foreach ($m in $members) {
                    $upn = $m.AdditionalProperties['userPrincipalName']
                    if ($upn) {
                        [void]$adminIds.Add($m.Id)
                        $adminUpnMap[$m.Id] = $upn
                    }
                }
            }
            catch { Write-Verbose "Could not get members for $($role.DisplayName): $_" }
        }

        $adminsWithoutMfa = [System.Collections.Generic.List[string]]::new()

        foreach ($adminId in $adminIds) {
            try {
                $methods = Get-MgUserAuthenticationMethod -UserId $adminId -All -ErrorAction Stop
                $hasMfaMethod = $methods | Where-Object {
                    $_.AdditionalProperties['@odata.type'] -in @(
                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                        '#microsoft.graph.fido2AuthenticationMethod',
                        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
                        '#microsoft.graph.phoneAuthenticationMethod',
                        '#microsoft.graph.softwareOathAuthenticationMethod'
                    )
                }
                if (-not $hasMfaMethod) {
                    $adminsWithoutMfa.Add($adminUpnMap[$adminId])
                }
            }
            catch { Write-Verbose "Could not check MFA methods for admin $adminId: $_" }
        }

        $results.Add((New-CheckResult `
            -CheckId        'MFA-002' `
            -Category       'Authentication' `
            -Name           'Admins Without MFA' `
            -Status         (if ($adminsWithoutMfa.Count -gt 0) { 'CRITICAL' } else { 'PASS' }) `
            -Detail         "$($adminsWithoutMfa.Count) of $($adminIds.Count) admin account(s) have no MFA method registered." `
            -Recommendation 'Require MFA registration immediately for all admins. Configure Conditional Access with phishing-resistant MFA strength for all privileged roles.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -CISControl     'CIS M365 1.1.1' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects $adminsWithoutMfa.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'MFA-002' `
            -Category       'Authentication' `
            -Name           'Admins Without MFA' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions. Required: RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.Directory and UserAuthenticationMethod.Read.All.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -CISControl     'CIS M365 1.1.1' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # MFA-003: MFA enforcement method (CA vs per-user vs Security Defaults)
    try {
        $secDefaults        = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
            -ErrorAction Stop
        $secDefaultsEnabled = $secDefaults.isEnabled

        $caPolicies  = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$filter=state eq 'enabled'&`$select=id,displayName,grantControls,conditions,state" `
            -ErrorAction Stop
        $enabledCa   = $caPolicies.value

        $caMfaForAll = $enabledCa | Where-Object {
            $_.grantControls.builtInControls -contains 'mfa' -and
            $_.conditions.users.includeUsers -contains 'All'
        }
        $caMfaForAdmins = $enabledCa | Where-Object {
            $_.grantControls.builtInControls -contains 'mfa' -and
            $_.conditions.users.includeRoles.Count -gt 0
        }

        $enforcement = if ($caMfaForAll.Count -gt 0) {
            "Conditional Access (recommended): MFA enforced for all users via $($caMfaForAll.Count) CA policy/policies"
        }
        elseif ($secDefaultsEnabled) {
            "Security Defaults: MFA prompted at Microsoft's discretion"
        }
        elseif ($caMfaForAdmins.Count -gt 0) {
            "Conditional Access for admins only: $($caMfaForAdmins.Count) policy/policies enforce MFA for admin roles, but not all users"
        }
        else {
            "Per-user MFA or no enforcement detected: No CA policy requires MFA for all users, Security Defaults disabled"
        }

        $perUserOnly = (-not $secDefaultsEnabled -and $caMfaForAll.Count -eq 0 -and $caMfaForAdmins.Count -eq 0)

        $results.Add((New-CheckResult `
            -CheckId        'MFA-003' `
            -Category       'Authentication' `
            -Name           'MFA Enforcement Method' `
            -Status         (if ($caMfaForAll.Count -gt 0) { 'PASS' } elseif ($perUserOnly) { 'HIGH' } else { 'MEDIUM' }) `
            -Detail         $enforcement `
            -Recommendation 'Use Conditional Access policies to enforce MFA for all users. Avoid relying on per-user MFA (legacy). Migrate per-user MFA settings to CA policies.' `
            -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' `
            -CISControl     'CIS M365 1.2.2' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'MFA-003' `
            -Category       'Authentication' `
            -Name           'MFA Enforcement Method' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # MFA-004: Passwordless authentication adoption
    if ($regDetails) {
        try {
            $passwordlessMethods = @(
                'microsoftAuthenticatorAuthenticationMethod',
                'fido2AuthenticationMethod',
                'windowsHelloForBusinessAuthenticationMethod'
            )
            $passwordlessUsers = $regDetails | Where-Object {
                $_.MethodsRegistered | Where-Object { $_ -in $passwordlessMethods }
            }
            $totalUsers        = $regDetails.Count
            $passwordlessCount = $passwordlessUsers.Count
            $pct = if ($totalUsers -gt 0) { [math]::Round(($passwordlessCount / $totalUsers) * 100, 1) } else { 0 }

            $results.Add((New-CheckResult `
                -CheckId        'MFA-004' `
                -Category       'Authentication' `
                -Name           'Passwordless Authentication Adoption' `
                -Status         'INFO' `
                -Detail         "$passwordlessCount of $totalUsers users ($pct%) have a passwordless method registered (Authenticator passwordless, FIDO2, or Windows Hello for Business)." `
                -Recommendation 'Drive passwordless adoption. Start with admins, then IT staff, then all users. Authenticator passwordless sign-in and FIDO2 keys are phishing-resistant.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId        'MFA-004' `
                -Category       'Authentication' `
                -Name           'Passwordless Authentication Adoption' `
                -Status         'INFO' `
                -Detail         "Failed to process passwordless data: $_" `
                -Recommendation '' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }

    # MFA-005: Average registered auth methods per user
    if ($regDetails) {
        try {
            $totalUsers = $regDetails.Count
            if ($totalUsers -gt 0) {
                $totalMethods = ($regDetails | Measure-Object -Property { $_.MethodsRegistered.Count } -Sum).Sum
                $avgMethods   = [math]::Round($totalMethods / $totalUsers, 2)
            }
            else {
                $avgMethods = 0
            }

            $checkStatus = if ($avgMethods -ge 2) { 'PASS' } elseif ($avgMethods -ge 1.5) { 'MEDIUM' } else { 'LOW' }

            $results.Add((New-CheckResult `
                -CheckId        'MFA-005' `
                -Category       'Authentication' `
                -Name           'Average Auth Methods per User' `
                -Status         $checkStatus `
                -Detail         "Average registered authentication methods per user: $avgMethods (total users: $totalUsers). Fewer than 2 methods per user creates lockout risk if primary method is unavailable." `
                -Recommendation 'Encourage users to register at least 2 authentication methods (e.g., Authenticator app + backup phone/email). Use the registration campaign to prompt re-registration.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId        'MFA-005' `
                -Category       'Authentication' `
                -Name           'Average Auth Methods per User' `
                -Status         'INFO' `
                -Detail         "Failed to calculate average: $_" `
                -Recommendation '' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }

    return $results
}
