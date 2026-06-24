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
        $results.Add((New-AssessmentResult `
            -CheckName 'MFA-000: Registration Report Access' `
            -Status    'Info' `
            -Detail    "Could not retrieve authentication method registration details. MFA-001, MFA-004, MFA-005 skipped. Required: Reports.Read.All. Error: $_" `
            -Recommendation 'Grant Reports.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/graph/api/reportroot-list-credentialuserregistrationdetails' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # MFA-001: MFA registration rate (all users)
    if ($regDetails) {
        try {
            $totalUsers = $regDetails.Count
            $mfaRegistered = ($regDetails | Where-Object { $_.IsMfaRegistered -eq $true }).Count
            $pct = if ($totalUsers -gt 0) { [math]::Round(($mfaRegistered / $totalUsers) * 100, 1) } else { 0 }

            $status   = if ($pct -ge 95) { 'Pass' } elseif ($pct -ge 80) { 'Warning' } else { 'Fail' }
            $severity = if ($pct -lt 50) { 'Critical' } elseif ($pct -lt 80) { 'High' } elseif ($pct -lt 95) { 'Medium' } else { 'Info' }

            $results.Add((New-AssessmentResult `
                -CheckName 'MFA-001: MFA Registration Rate' `
                -Status    $status `
                -Detail    "$mfaRegistered of $totalUsers users have MFA registered ($pct%). Target: 95%+." `
                -Recommendation 'Enable the authentication methods registration campaign. Enforce MFA registration via Conditional Access (require registration as grant control). Target 100%.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
                -Category  'Authentication' `
                -Severity  $severity `
                -MitreId   'T1110.003' `
                -MitreTactic 'CredentialAccess' `
                -CisControl 'CIS M365 1.1.2'))
        }
        catch {
            $results.Add((New-AssessmentResult `
                -CheckName 'MFA-001: MFA Registration Rate' `
                -Status    'Info' `
                -Detail    "Failed to process registration details: $_" `
                -Recommendation '' `
                -Category  'Authentication' `
                -Severity  'Info'))
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

        $adminIds = [System.Collections.Generic.HashSet[string]]::new()
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

        $status = if ($adminsWithoutMfa.Count -eq 0) { 'Pass' } else { 'Fail' }
        $affectedList = $adminsWithoutMfa -join ', '

        $results.Add((New-AssessmentResult `
            -CheckName 'MFA-002: Admins Without MFA' `
            -Status    $status `
            -Detail    "$($adminsWithoutMfa.Count) of $($adminIds.Count) admin account(s) have no MFA method registered. Affected: $affectedList" `
            -Recommendation 'Require MFA registration immediately for all admins. Configure Conditional Access with phishing-resistant MFA strength for all privileged roles.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -Category  'Authentication' `
            -Severity  (if ($adminsWithoutMfa.Count -gt 0) { 'Critical' } else { 'Info' }) `
            -MitreId   'T1111' `
            -MitreTactic 'CredentialAccess' `
            -CisControl 'CIS M365 1.1.1'))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'MFA-002: Admins Without MFA' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: RoleManagement.Read.Directory, UserAuthenticationMethod.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.Directory and UserAuthenticationMethod.Read.All.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # MFA-003: MFA enforcement method (CA vs per-user vs Security Defaults)
    try {
        # Check Security Defaults
        $secDefaults = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
            -ErrorAction Stop
        $secDefaultsEnabled = $secDefaults.isEnabled

        # Check CA policies requiring MFA
        $caPolicies = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$filter=state eq 'enabled'&`$select=id,displayName,grantControls,conditions,state" `
            -ErrorAction Stop
        $enabledCa = $caPolicies.value

        $caMfaForAll = $enabledCa | Where-Object {
            $grant = $_.grantControls
            $conditions = $_.conditions
            $grant.builtInControls -contains 'mfa' -and
            $conditions.users.includeUsers -contains 'All'
        }
        $caMfaForAdmins = $enabledCa | Where-Object {
            $grant = $_.grantControls
            $grant.builtInControls -contains 'mfa' -and
            $_.conditions.users.includeRoles.Count -gt 0
        }

        # Per-user MFA: detected via registration details having isMfaRegistered but no CA MFA
        # We can only detect if per-user MFA is the primary method by absence of CA enforcement
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

        $noEnforcement = (-not $secDefaultsEnabled -and $caMfaForAll.Count -eq 0 -and $caMfaForAdmins.Count -eq 0)
        $perUserOnly = (-not $secDefaultsEnabled -and $caMfaForAll.Count -eq 0 -and $caMfaForAdmins.Count -eq 0)

        $results.Add((New-AssessmentResult `
            -CheckName 'MFA-003: MFA Enforcement Method' `
            -Status    (if ($caMfaForAll.Count -gt 0) { 'Pass' } elseif ($perUserOnly) { 'Fail' } else { 'Warning' }) `
            -Detail    $enforcement `
            -Recommendation 'Use Conditional Access policies to enforce MFA for all users. Avoid relying on per-user MFA (legacy, cannot be scoped to conditions). Migrate per-user MFA settings to CA policies.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' `
            -Category  'Authentication' `
            -Severity  (if ($perUserOnly) { 'High' } else { 'Medium' }) `
            -MitreId   'T1110.003' `
            -MitreTactic 'CredentialAccess' `
            -CisControl 'CIS M365 1.2.2'))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'MFA-003: MFA Enforcement Method' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # MFA-004: Passwordless authentication adoption
    if ($regDetails) {
        try {
            $passwordlessMethods = @(
                'microsoftAuthenticatorAuthenticationMethod',  # Authenticator passwordless
                'fido2AuthenticationMethod',
                'windowsHelloForBusinessAuthenticationMethod'
            )

            $passwordlessUsers = $regDetails | Where-Object {
                $_.MethodsRegistered | Where-Object { $_ -in $passwordlessMethods }
            }
            $totalUsers = $regDetails.Count
            $passwordlessCount = $passwordlessUsers.Count
            $pct = if ($totalUsers -gt 0) { [math]::Round(($passwordlessCount / $totalUsers) * 100, 1) } else { 0 }

            $results.Add((New-AssessmentResult `
                -CheckName 'MFA-004: Passwordless Authentication Adoption' `
                -Status    'Info' `
                -Detail    "$passwordlessCount of $totalUsers users ($pct%) have a passwordless method registered (Authenticator passwordless, FIDO2, or Windows Hello for Business)." `
                -Recommendation 'Drive passwordless adoption. Start with admins, then IT staff, then all users. Authenticator passwordless sign-in and FIDO2 keys are phishing-resistant.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless' `
                -Category  'Authentication' `
                -Severity  'Info' `
                -CisControl ''))
        }
        catch {
            $results.Add((New-AssessmentResult `
                -CheckName 'MFA-004: Passwordless Adoption' `
                -Status    'Info' `
                -Detail    "Failed to process passwordless data: $_" `
                -Recommendation '' `
                -Category  'Authentication' `
                -Severity  'Info'))
        }
    }

    # MFA-005: Average registered auth methods per user
    if ($regDetails) {
        try {
            $totalUsers = $regDetails.Count
            if ($totalUsers -gt 0) {
                $totalMethods = ($regDetails | Measure-Object -Property { $_.MethodsRegistered.Count } -Sum).Sum
                $avgMethods = [math]::Round($totalMethods / $totalUsers, 2)
            }
            else {
                $avgMethods = 0
            }

            $status   = if ($avgMethods -ge 2) { 'Pass' } elseif ($avgMethods -ge 1.5) { 'Warning' } else { 'Fail' }
            $severity = if ($avgMethods -lt 1.5) { 'Low' } else { 'Info' }

            $results.Add((New-AssessmentResult `
                -CheckName 'MFA-005: Average Auth Methods per User' `
                -Status    $status `
                -Detail    "Average registered authentication methods per user: $avgMethods (total users: $totalUsers). Fewer than 2 methods per user creates lockout risk if primary method is unavailable." `
                -Recommendation 'Encourage users to register at least 2 authentication methods (e.g., Authenticator app + backup phone/email). Use the registration campaign to prompt re-registration.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
                -Category  'Authentication' `
                -Severity  $severity `
                -CisControl ''))
        }
        catch {
            $results.Add((New-AssessmentResult `
                -CheckName 'MFA-005: Average Auth Methods' `
                -Status    'Info' `
                -Detail    "Failed to calculate average: $_" `
                -Recommendation '' `
                -Category  'Authentication' `
                -Severity  'Info'))
        }
    }

    return $results
}
