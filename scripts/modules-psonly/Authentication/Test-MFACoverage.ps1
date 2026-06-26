#Requires -Version 7.0

<#
.SYNOPSIS
    Checks MFA registration coverage and enforcement quality across the tenant. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — replaces raw Invoke-MgGraphRequest calls for Security Defaults
    and CA policies with:
        Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
        Get-MgIdentityConditionalAccessPolicy -All

    All other cmdlets (Get-MgReportAuthenticationMethodUserRegistrationDetail,
    Get-MgDirectoryRole, Get-MgDirectoryRoleMember, Get-MgUserAuthenticationMethod)
    were already native PS cmdlets in the original and are retained as-is.

    WHY PS-ONLY:
    The original Test-MFACoverage.ps1 uses Invoke-MgGraphRequest for the Security
    Defaults endpoint and CA policy listing. These have direct PS-only equivalents:
    - /policies/identitySecurityDefaultsEnforcementPolicy
      → Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    - /identity/conditionalAccess/policies
      → Get-MgIdentityConditionalAccessPolicy -All -Filter "state eq 'enabled'"

    SEE ALSO (Graph variant):
        scripts/modules/Authentication/Test-MFACoverage.ps1

    Required connection:
        Connect-MgGraph -Scopes "Reports.Read.All","UserAuthenticationMethod.Read.All","Policy.Read.All","RoleManagement.Read.Directory","Directory.Read.All"

    Required scopes:
        Reports.Read.All
        UserAuthenticationMethod.Read.All
        Policy.Read.All
        RoleManagement.Read.Directory
        Directory.Read.All

    Required modules:
        Microsoft.Graph.Reports
        Microsoft.Graph.Identity.DirectoryManagement
        Microsoft.Graph.Identity.SignIns

    License: E3 minimum; per-user MFA status requires Reports.Read.All
    SC-300 Domain: Authentication & Access Management

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-MFACoverage {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Fetch credential registration details once — MFA-001, MFA-004, MFA-005
    # -------------------------------------------------------------------------
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
            -Recommendation 'Connect-MgGraph -Scopes "Reports.Read.All".' `
            -Reference      'https://learn.microsoft.com/graph/api/reportroot-list-credentialuserregistrationdetails' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MFA-001: MFA registration rate (all users)
    # -------------------------------------------------------------------------
    if ($regDetails) {
        try {
            $totalUsers    = $regDetails.Count
            $mfaRegistered = ($regDetails | Where-Object { $_.IsMfaRegistered -eq $true }).Count
            $pct           = if ($totalUsers -gt 0) { [math]::Round(($mfaRegistered / $totalUsers) * 100, 1) } else { 0 }

            $mfa001Status = if ($pct -ge 95) { 'PASS' } elseif ($pct -ge 80) { 'MEDIUM' } elseif ($pct -ge 50) { 'HIGH' } else { 'CRITICAL' }

            $results.Add((New-CheckResult `
                -CheckId        'MFA-001' `
                -Category       'Authentication' `
                -Name           'MFA Registration Rate' `
                -Status         $mfa001Status `
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

    # -------------------------------------------------------------------------
    # MFA-002: Admins without MFA
    # -------------------------------------------------------------------------
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

        $adminIds    = [System.Collections.Generic.HashSet[string]]::new()
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
            -Recommendation 'Connect-MgGraph -Scopes "RoleManagement.Read.Directory","UserAuthenticationMethod.Read.All".' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -CISControl     'CIS M365 1.1.1' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MFA-003: MFA enforcement method
    # PS-ONLY: Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
    #          Get-MgIdentityConditionalAccessPolicy -All
    # -------------------------------------------------------------------------
    try {
        $secDefaultsPolicy  = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        $secDefaultsEnabled = $secDefaultsPolicy.IsEnabled

        $enabledCaPolicies = Get-MgIdentityConditionalAccessPolicy `
            -Filter "state eq 'enabled'" `
            -All `
            -ErrorAction Stop

        $caMfaForAll = @($enabledCaPolicies | Where-Object {
            $_.GrantControls.BuiltInControls -contains 'mfa' -and
            $_.Conditions.Users.IncludeUsers -contains 'All'
        })
        $caMfaForAdmins = @($enabledCaPolicies | Where-Object {
            $_.GrantControls.BuiltInControls -contains 'mfa' -and
            $_.Conditions.Users.IncludeRoles.Count -gt 0
        })

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
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
            -Reference      'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MFA-004: Passwordless authentication adoption
    # -------------------------------------------------------------------------
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
            $passwordlessCount = ($passwordlessUsers | Measure-Object).Count
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

    # -------------------------------------------------------------------------
    # MFA-005: Average registered auth methods per user
    # -------------------------------------------------------------------------
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

            $mfa005Status = if ($avgMethods -ge 2) { 'PASS' } elseif ($avgMethods -ge 1.5) { 'MEDIUM' } else { 'LOW' }

            $results.Add((New-CheckResult `
                -CheckId        'MFA-005' `
                -Category       'Authentication' `
                -Name           'Average Auth Methods per User' `
                -Status         $mfa005Status `
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
