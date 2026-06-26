#Requires -Version 7.0

<#
.SYNOPSIS
    Checks Entra ID guest account hygiene and external access risk. PS-only variant.

.DESCRIPTION
    Evaluates total guest volume, stale guests (90+ days), invite settings,
    guest directory access level, and guests with privileged roles.
    Checks: GST-001 through GST-005.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/Identity/Test-GuestAccounts.ps1

    CHANGES vs. Graph variant:
        GST-001/GST-002: Get-MgUser -Filter already used in original — unchanged.
        GST-003/GST-004: Get-MgPolicyAuthorizationPolicy already used — unchanged.
        GST-005: Get-MgDirectoryRole -All and Get-MgDirectoryRoleMember already used — unchanged.
        This file is structurally identical to the original; no Invoke-MgGraphRequest calls
        were present in the guest-specific logic. Included here for completeness and to ensure
        the modules-psonly directory has a self-contained, consistent set.

.NOTES
    Required connection  : Connect-MgGraph -Scopes "User.Read.All","AuditLog.Read.All","Policy.Read.All","Directory.Read.All"
    Required scopes      : User.Read.All, AuditLog.Read.All, Policy.Read.All,
                           RoleManagement.Read.Directory, Directory.Read.All
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Users
                           Microsoft.Graph.Identity.DirectoryManagement

    License: E3 minimum; signInActivity requires AuditLog.Read.All.
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-GuestAccounts {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $allGuests = $null
    $totalUserCount = 0

    # GST-001: Total guest accounts and percentage
    try {
        $allGuests = Get-MgUser -Filter "userType eq 'Guest'" `
            -Property 'id,displayName,userPrincipalName,accountEnabled,signInActivity,createdDateTime' `
            -All -ErrorAction Stop

        $guestCount = $allGuests.Count

        $allUsers = Get-MgUser -Filter "accountEnabled eq true" -Property 'id' -All -ErrorAction Stop
        $totalUserCount = $allUsers.Count
        $guestPct = if ($totalUserCount -gt 0) { [math]::Round(($guestCount / $totalUserCount) * 100, 1) } else { 0 }

        $status = if ($guestPct -gt 30) { 'Fail' } elseif ($guestPct -gt 15) { 'Warning' } else { 'Pass' }

        $results.Add((New-CheckResult `
            -CheckName 'GST-001: Guest Account Volume' `
            -Status    $status `
            -Detail    "$guestCount guest account(s) in directory ($guestPct% of $totalUserCount enabled users). Large guest populations increase external attack surface." `
            -Recommendation 'Review guest accounts regularly. Implement Entra ID Governance Access Reviews for guests. Remove inactive or unauthorized guests.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
            -Category  'Identity' `
            -Severity  (if ($guestPct -gt 30) { 'High' } else { 'Medium' }) `
            -MitreId   'T1078' `
            -MitreTactic 'InitialAccess' `
            -CisControl 'CIS M365 1.3.1'))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'GST-001: Guest Account Volume' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: User.Read.All. Error: $_" `
            -Recommendation 'Grant User.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/access-reviews-overview' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # GST-002: Stale guests (no sign-in for 90+ days)
    try {
        $guests = if ($allGuests) { $allGuests } else {
            Get-MgUser -Filter "userType eq 'Guest'" `
                -Property 'id,displayName,userPrincipalName,accountEnabled,signInActivity,createdDateTime' `
                -All -ErrorAction Stop
        }

        $staleGuests = $guests | Where-Object {
            $lastSignIn = $_.SignInActivity.LastSignInDateTime
            $null -eq $lastSignIn -or $lastSignIn -lt (Get-Date).AddDays(-90)
        }

        $staleCount = $staleGuests.Count
        $staleUpns = ($staleGuests | Select-Object -First 20 -ExpandProperty UserPrincipalName) -join ', '

        $results.Add((New-CheckResult `
            -CheckName 'GST-002: Stale Guest Accounts (90+ Days)' `
            -Status    (if ($staleCount -eq 0) { 'Pass' } elseif ($staleCount -lt 10) { 'Warning' } else { 'Fail' }) `
            -Detail    "$staleCount guest(s) with no sign-in in 90+ days. Sample: $staleUpns" `
            -Recommendation 'Remove or disable stale guest accounts. Configure Entra ID Governance Access Reviews on a quarterly basis for all guest users.' `
            -Reference 'https://learn.microsoft.com/entra/identity/users/clean-up-stale-guest-accounts' `
            -Category  'Identity' `
            -Severity  'Medium' `
            -MitreId   'T1078' `
            -MitreTactic 'Persistence' `
            -CisControl 'CIS M365 1.3.2'))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'GST-002: Stale Guest Accounts' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: User.Read.All, AuditLog.Read.All. Error: $_" `
            -Recommendation 'Grant User.Read.All and AuditLog.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/users/clean-up-stale-guest-accounts' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # GST-003: Guest invite settings
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $allowInvitesFrom = $authPolicy.AllowInvitesFrom

        $status = switch ($allowInvitesFrom) {
            'admins'                          { 'Pass' }
            'adminsAndGuestInviters'          { 'Pass' }
            'adminsGuestInvitersAndMembers'   { 'Warning' }
            'everyone'                        { 'Fail' }
            default                           { 'Warning' }
        }
        $severity = if ($allowInvitesFrom -eq 'everyone') { 'High' } elseif ($allowInvitesFrom -eq 'adminsGuestInvitersAndMembers') { 'Medium' } else { 'Info' }

        $results.Add((New-CheckResult `
            -CheckName 'GST-003: Guest Invite Permissions' `
            -Status    $status `
            -Detail    "AllowInvitesFrom: '$allowInvitesFrom'. Setting 'everyone' allows any user in the tenant to invite external guests without admin oversight." `
            -Recommendation "Set AllowInvitesFrom to 'admins' or 'adminsAndGuestInviters' to restrict who can send B2B invitations." `
            -Reference 'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure' `
            -Category  'Identity' `
            -Severity  $severity `
            -MitreId   'T1087.004' `
            -MitreTactic 'Discovery' `
            -CisControl 'CIS M365 1.3.3'))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'GST-003: Guest Invite Permissions' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/external-collaboration-settings-configure' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # GST-004: Guest access restrictions (directory visibility)
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
        $guestRoleId = $authPolicy.GuestUserRoleId

        $levelName = switch ($guestRoleId) {
            '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Restricted Guest User (most restrictive)' }
            'bf6b4499-ff22-4af0-a0ee-2c280a9d66bb' { 'Guest User (default)' }
            'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Same access as members (least restrictive)' }
            default                                  { "Unknown ($guestRoleId)" }
        }

        $status = switch ($guestRoleId) {
            '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Pass' }
            'bf6b4499-ff22-4af0-a0ee-2c280a9d66bb' { 'Warning' }
            'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Fail' }
            default                                  { 'Warning' }
        }

        $results.Add((New-CheckResult `
            -CheckName 'GST-004: Guest Directory Access Level' `
            -Status    $status `
            -Detail    "Guest user access level: $levelName. Member-like access allows guests to enumerate users, groups, and other directory objects." `
            -Recommendation "Set guest access to 'Restricted Guest User' to prevent directory enumeration by external users." `
            -Reference 'https://learn.microsoft.com/entra/fundamentals/users-default-permissions#member-and-guest-users' `
            -Category  'Identity' `
            -Severity  (if ($guestRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') { 'High' } else { 'Medium' }) `
            -MitreId   'T1087.004' `
            -MitreTactic 'Discovery' `
            -CisControl 'CIS M365 1.3.1'))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'GST-004: Guest Directory Access Level' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/fundamentals/users-default-permissions' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # GST-005: Guests with privileged roles
    try {
        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $privilegedRoleNames = @(
            'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
            'User Administrator', 'Exchange Administrator', 'SharePoint Administrator',
            'Teams Administrator', 'Billing Administrator', 'Compliance Administrator',
            'Application Administrator', 'Cloud Application Administrator',
            'Authentication Administrator', 'Privileged Authentication Administrator'
        )
        $privilegedRoles = $allRoles | Where-Object { $_.DisplayName -in $privilegedRoleNames }

        $guestsInRoles = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($role in $privilegedRoles) {
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
                foreach ($member in $members) {
                    $userType = $member.AdditionalProperties['userType']
                    if ($userType -eq 'Guest') {
                        $guestsInRoles.Add([PSCustomObject]@{
                            UPN      = $member.AdditionalProperties['userPrincipalName']
                            RoleName = $role.DisplayName
                        })
                    }
                }
            }
            catch { Write-Verbose "Could not enumerate members for role $($role.DisplayName): $_" }
        }

        if ($guestsInRoles.Count -gt 0) {
            $detail = ($guestsInRoles | ForEach-Object { "$($_.UPN) [$($_.RoleName)]" }) -join '; '
            $results.Add((New-CheckResult `
                -CheckName 'GST-005: Guests with Privileged Roles' `
                -Status    'Fail' `
                -Detail    "$($guestsInRoles.Count) guest(s) found in privileged roles: $detail" `
                -Recommendation 'Remove all guest accounts from privileged Entra ID roles immediately. Guest accounts should never hold administrative permissions.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
                -Category  'Identity' `
                -Severity  'Critical' `
                -MitreId   'T1098.003' `
                -MitreTactic 'Persistence' `
                -CisControl 'CIS M365 1.3.6'))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckName 'GST-005: Guests with Privileged Roles' `
                -Status    'Pass' `
                -Detail    "No guest accounts found in privileged Entra ID roles ($($privilegedRoles.Count) roles checked)." `
                -Recommendation 'Continue to audit periodically. Add this check to quarterly access reviews.' `
                -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl 'CIS M365 1.3.6'))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckName 'GST-005: Guests with Privileged Roles' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: RoleManagement.Read.Directory. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.Directory and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    return $results
}
