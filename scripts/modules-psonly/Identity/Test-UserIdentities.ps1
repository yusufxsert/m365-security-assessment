#Requires -Version 7.0

<#
.SYNOPSIS
    Checks Entra ID user account hygiene and identity risk indicators. PS-only variant.

.DESCRIPTION
    Evaluates unlicensed active accounts, stale accounts (90+ days no sign-in),
    MFA registration gaps, risky sign-in patterns, and Global Admin count.
    Checks: USR-001 through USR-005.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/Identity/Test-UserIdentities.ps1

    CHANGES vs. Graph variant:
        USR-001/USR-002: Get-MgUser -Filter already used in original — unchanged.
        USR-003: Get-MgReportAuthenticationMethodUserRegistrationDetail already used — unchanged.
        USR-004: Invoke-MgGraphRequest GET /auditLogs/signIns with riskLevelAggregated filter
                 -> Get-MgAuditLogSignIn -Filter "riskLevelAggregated eq 'high' and createdDateTime ge {date}"
                 NOTE: riskLevelAggregated is a beta-only property. The v1.0 signIns endpoint
                 accepts the filter but may return empty results if the tenant does not have
                 Entra ID P2 / Identity Protection. An INFO stub is returned in that case.
        USR-005: Get-MgDirectoryRole -All and Get-MgDirectoryRoleMember already used — unchanged.

.NOTES
    Required connection  : Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Reports.Read.All","Directory.Read.All"
    Required scopes      : User.Read.All, AuditLog.Read.All, Reports.Read.All,
                           RoleManagement.Read.Directory, Directory.Read.All
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Users
                           Microsoft.Graph.Identity.DirectoryManagement
                           Microsoft.Graph.Reports

    License: E3 minimum; AuditLog requires E3+; risk data requires Entra ID P2.
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-UserIdentities {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # USR-001: Unlicensed users with active accounts
    try {
        $enabledUsers = Get-MgUser -Filter "accountEnabled eq true" `
            -Property 'id,displayName,userPrincipalName,assignedLicenses' `
            -All -ErrorAction Stop

        $totalEnabled = $enabledUsers.Count
        $unlicensed = $enabledUsers | Where-Object { $_.AssignedLicenses.Count -eq 0 }
        $unlicensedCount = $unlicensed.Count

        $pct = if ($totalEnabled -eq 0) { 0 } else {
            [math]::Round(($unlicensedCount / $totalEnabled) * 100, 1)
        }

        $status = if ($pct -gt 10) { 'Fail' } elseif ($pct -gt 5) { 'Warning' } else { 'Pass' }
        $affectedUpns = ($unlicensed | Select-Object -First 20 -ExpandProperty UserPrincipalName) -join ', '

        $results.Add((New-CheckResult `
            -CheckName 'USR-001: Unlicensed Active Users' `
            -Status    $status `
            -Detail    "$unlicensedCount of $totalEnabled enabled users have no assigned license ($pct%). Sample: $affectedUpns" `
            -Recommendation 'Disable or delete enabled accounts with no license assignment. Unlicensed accounts that are enabled pose an unnecessary attack surface.' `
            -Reference 'https://learn.microsoft.com/entra/identity/users/licensing-groups-resolve-problems' `
            -Category  'Identity' `
            -Severity  (if ($pct -gt 10) { 'High' } else { 'Medium' }) `
            -MitreId   'T1078' `
            -MitreTactic 'InitialAccess' `
            -CisControl 'CIS M365 1.1.4'))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'USR-001: Unlicensed Active Users' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: User.Read.All. Error: $_" `
            -Recommendation 'Grant User.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/users/licensing-groups-resolve-problems' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # USR-002: Stale accounts (enabled, no sign-in for 90+ days)
    try {
        $enabledUsers = Get-MgUser -Filter "accountEnabled eq true" `
            -Property 'id,displayName,userPrincipalName,signInActivity' `
            -All -ErrorAction Stop

        $staleUsers = $enabledUsers | Where-Object {
            $lastSignIn = $_.SignInActivity.LastSignInDateTime
            $null -eq $lastSignIn -or $lastSignIn -lt (Get-Date).AddDays(-90)
        }

        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $privilegedRoleNames = @(
            'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
            'Exchange Administrator', 'SharePoint Administrator', 'Teams Administrator',
            'Compliance Administrator', 'Privileged Authentication Administrator'
        )
        $privilegedRoles = $allRoles | Where-Object { $_.DisplayName -in $privilegedRoleNames }

        $adminIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($role in $privilegedRoles) {
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
                foreach ($m in $members) { [void]$adminIds.Add($m.Id) }
            }
            catch { Write-Verbose "Could not get members for role $($role.DisplayName): $_" }
        }

        $staleAdmins  = $staleUsers | Where-Object { $adminIds.Contains($_.Id) }
        $staleRegular = $staleUsers | Where-Object { -not $adminIds.Contains($_.Id) }

        $staleAdminUpns    = ($staleAdmins | Select-Object -ExpandProperty UserPrincipalName) -join ', '
        $staleRegularSample = ($staleRegular | Select-Object -First 10 -ExpandProperty UserPrincipalName) -join ', '

        if ($staleAdmins.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckName 'USR-002: Stale Admin Accounts (90+ Days)' `
                -Status    'Fail' `
                -Detail    "$($staleAdmins.Count) admin account(s) have not signed in for 90+ days: $staleAdminUpns" `
                -Recommendation 'Immediately review and disable/delete stale admin accounts. Stale privileged accounts are a critical persistence risk.' `
                -Reference 'https://learn.microsoft.com/entra/identity/users/clean-up-stale-guest-accounts' `
                -Category  'Identity' `
                -Severity  'Critical' `
                -MitreId   'T1078.004' `
                -MitreTactic 'Persistence' `
                -CisControl 'CIS M365 1.1.4'))
        }

        $regularStatus = if ($staleRegular.Count -eq 0) { 'Pass' } elseif ($staleRegular.Count -lt 10) { 'Warning' } else { 'Fail' }
        $results.Add((New-CheckResult `
            -CheckName 'USR-002: Stale User Accounts (90+ Days)' `
            -Status    $regularStatus `
            -Detail    "$($staleRegular.Count) enabled non-admin user account(s) have not signed in for 90+ days. Sample: $staleRegularSample" `
            -Recommendation 'Disable accounts inactive for 90+ days. Implement a lifecycle process to automatically disable accounts after inactivity.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/lifecycle-workflows-overview' `
            -Category  'Identity' `
            -Severity  'Medium' `
            -MitreId   'T1078' `
            -MitreTactic 'Persistence' `
            -CisControl 'CIS M365 1.1.4'))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'USR-002: Stale Accounts' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: User.Read.All, AuditLog.Read.All. Error: $_" `
            -Recommendation 'Grant User.Read.All and AuditLog.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/users/clean-up-stale-guest-accounts' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # USR-003: Users without MFA registered
    try {
        $regDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All -ErrorAction Stop

        $totalUsers  = $regDetails.Count
        $withMfa     = ($regDetails | Where-Object { $_.IsMfaRegistered -eq $true }).Count
        $withoutMfa  = $totalUsers - $withMfa
        $pct = if ($totalUsers -gt 0) { [math]::Round(($withoutMfa / $totalUsers) * 100, 1) } else { 0 }

        $adminsWithoutMfa = $regDetails | Where-Object {
            $_.IsMfaRegistered -eq $false -and $_.IsAdmin -eq $true
        }
        $adminTotal = ($regDetails | Where-Object { $_.IsAdmin -eq $true }).Count
        $adminPct = if ($adminTotal -gt 0) {
            [math]::Round(($adminsWithoutMfa.Count / $adminTotal) * 100, 1)
        } else { 0 }

        if ($adminsWithoutMfa.Count -gt 0) {
            $adminUpns = ($adminsWithoutMfa | Select-Object -ExpandProperty UserPrincipalName) -join ', '
            $results.Add((New-CheckResult `
                -CheckName 'USR-003: Admins Without MFA Registered' `
                -Status    'Fail' `
                -Detail    "$($adminsWithoutMfa.Count) admin(s) have no MFA method registered ($adminPct% of admins): $adminUpns" `
                -Recommendation 'Immediately require MFA registration for all admins. Enforce via Conditional Access requiring MFA registration completion.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-methods' `
                -Category  'Identity' `
                -Severity  'Critical' `
                -MitreId   'T1111' `
                -MitreTactic 'CredentialAccess' `
                -CisControl 'CIS M365 1.1.1'))
        }

        $allUserStatus = if ($pct -le 5) { 'Pass' } elseif ($pct -le 20) { 'Warning' } else { 'Fail' }
        $results.Add((New-CheckResult `
            -CheckName 'USR-003: Users Without MFA Registered' `
            -Status    $allUserStatus `
            -Detail    "$withoutMfa of $totalUsers users ($pct%) have no MFA method registered." `
            -Recommendation 'Enable the registration campaign in Authentication Methods Policy. Enforce MFA registration via Conditional Access for all users.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
            -Category  'Identity' `
            -Severity  (if ($pct -gt 20) { 'High' } else { 'Medium' }) `
            -MitreId   'T1110.003' `
            -MitreTactic 'CredentialAccess' `
            -CisControl 'CIS M365 1.1.2'))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'USR-003: MFA Registration' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: Reports.Read.All. Error: $_" `
            -Recommendation 'Grant Reports.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-registration-mfa-sspr-combined' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # USR-004: Users with high-risk sign-in patterns
    # Uses Get-MgAuditLogSignIn with riskLevelAggregated filter.
    # NOTE: riskLevelAggregated is a beta property; on v1.0 it requires Entra ID P2.
    # If the tenant has no P2 / Identity Protection, the cmdlet returns an empty result set.
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $riskySignIns  = Get-MgAuditLogSignIn `
            -Filter "riskLevelAggregated eq 'high' and createdDateTime ge $thirtyDaysAgo" `
            -Top 100 `
            -ErrorAction Stop

        $riskyCount = if ($riskySignIns) { @($riskySignIns).Count } else { 0 }
        $uniqueRiskyUsers = if ($riskySignIns) {
            ($riskySignIns | Select-Object -ExpandProperty UserPrincipalName | Sort-Object -Unique).Count
        } else { 0 }

        $results.Add((New-CheckResult `
            -CheckName 'USR-004: High-Risk Sign-In Attempts (Last 30 Days)' `
            -Status    (if ($riskyCount -eq 0) { 'Pass' } else { 'Warning' }) `
            -Detail    "High-risk sign-in events in last 30 days: $riskyCount across $uniqueRiskyUsers unique user(s). NOTE: riskLevelAggregated data requires Entra ID P2 / Identity Protection. Zero results may indicate no P2 license rather than no risk." `
            -Recommendation 'Investigate risky sign-ins in Entra ID Protection. Configure risk-based CA policies to auto-block or require MFA for high-risk sign-ins.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -Category  'Identity' `
            -Severity  (if ($riskyCount -gt 0) { 'High' } else { 'Info' }) `
            -MitreId   'T1110' `
            -MitreTactic 'CredentialAccess' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'USR-004: Risky Sign-Ins' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: AuditLog.Read.All. Entra ID P2 license required for risk data. Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All and reconnect. Entra ID P2 license required for riskLevelAggregated data.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # USR-005: Global Admin count (should be 2-4)
    try {
        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $gaRole = $allRoles | Where-Object { $_.DisplayName -eq 'Global Administrator' } | Select-Object -First 1

        if (-not $gaRole) {
            $results.Add((New-CheckResult `
                -CheckName 'USR-005: Global Admin Count' `
                -Status    'Info' `
                -Detail    "Global Administrator role not found. This may indicate the role has no active members." `
                -Recommendation 'Verify tenant has at least 2 break-glass Global Admin accounts.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl 'CIS M365 1.1.2'))
        }
        else {
            $gaMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -All -ErrorAction Stop
            $gaCount = $gaMembers.Count

            $status = if ($gaCount -lt 2) { 'Fail' }
                      elseif ($gaCount -le 4) { 'Pass' }
                      elseif ($gaCount -le 8) { 'Warning' }
                      else { 'Fail' }

            $severity = if ($gaCount -lt 2) { 'Critical' } elseif ($gaCount -gt 8) { 'High' } else { 'Info' }

            $detail = if ($gaCount -lt 2) {
                "Only $gaCount Global Administrator(s) found. Single point of failure — if this account is compromised or locked, tenant recovery may be impossible."
            } elseif ($gaCount -gt 5) {
                "$gaCount Global Administrators found (recommended: 2-4). Excess privileged accounts increase the attack surface."
            } else {
                "$gaCount Global Administrators found. This is within the recommended range of 2-4."
            }

            $results.Add((New-CheckResult `
                -CheckName 'USR-005: Global Admin Count' `
                -Status    $status `
                -Detail    $detail `
                -Recommendation 'Maintain 2-4 Global Admin accounts (break-glass only). Use scoped admin roles via PIM for day-to-day tasks.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
                -Category  'Identity' `
                -Severity  $severity `
                -MitreId   'T1078.004' `
                -MitreTactic 'PrivilegeEscalation' `
                -CisControl 'CIS M365 1.1.2'))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'USR-005: Global Admin Count' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: RoleManagement.Read.Directory. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.Directory and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    return $results
}
