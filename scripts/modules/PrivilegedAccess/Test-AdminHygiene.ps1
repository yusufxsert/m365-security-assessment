#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests administrative account hygiene for Microsoft 365 tenant.

.DESCRIPTION
    Checks whether admin accounts are dedicated (separate from daily-use accounts),
    follow naming conventions, use strong MFA methods, are actively used,
    adhere to least-privilege, and do not have active mailboxes that could
    serve as phishing vectors.

.NOTES
    Required Permissions:
        - RoleManagement.Read.All
        - User.Read.All
        - AuditLog.Read.All
        - UserAuthenticationMethod.Read.All

    License: Microsoft 365 E3 / E5
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
#>

function Test-AdminHygiene {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Well-known role IDs
    $gaRoleDefId            = '62e90394-69f5-4237-9190-012177145e10'
    $praRoleDefId           = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
    $secAdminRoleDefId      = '194ae4cb-b126-40b2-bd5b-6091b380977d'

    # Productivity license SKU part numbers (E3/E5 include Exchange mailbox)
    $mailboxLicenseSkus = @(
        'ENTERPRISEPREMIUM',  # Office 365 E5
        'ENTERPRISEPACK',     # Office 365 E3
        'SPE_E5',             # Microsoft 365 E5
        'SPE_E3',             # Microsoft 365 E3
        'EXCHANGESTANDARD',   # Exchange Online Plan 1
        'EXCHANGEENTERPRISE', # Exchange Online Plan 2
        'O365_BUSINESS_PREMIUM',
        'SMB_BUSINESS_PREMIUM'
    )

    # Helper: retrieve all permanent active role members across all roles
    function Get-AllPrivilegedUsers {
        $uri = 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?$expand=principal&$top=999'
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        # Include both permanent and currently PIM-activated users
        return $response.value | Where-Object {
            $_.principal.'@odata.type' -eq '#microsoft.graph.user'
        }
    }

    # Helper: get members of a specific role (both permanent and eligible/active)
    function Get-RoleMembers {
        param([string]$RoleDefinitionId)
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$filter=roleDefinitionId eq '$RoleDefinitionId'&`$expand=principal&`$top=999"
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        return $response.value | Where-Object {
            $_.principal.'@odata.type' -eq '#microsoft.graph.user'
        }
    }

    # -------------------------------------------------------------------------
    # ADM-001: Admin accounts dedicated (separate from daily-use)
    # -------------------------------------------------------------------------
    try {
        $allPrivUsers = Get-AllPrivilegedUsers
        # Unique user IDs (a user may hold multiple roles)
        $uniqueAdminIds = $allPrivUsers | Select-Object -ExpandProperty principalId -Unique

        $dualPurposeAdmins = [System.Collections.Generic.List[string]]::new()

        foreach ($adminId in $uniqueAdminIds) {
            $licUri = "https://graph.microsoft.com/v1.0/users/$adminId`?`$select=id,displayName,userPrincipalName,assignedLicenses"
            try {
                $userDetail = Invoke-MgGraphRequest -Method GET -Uri $licUri -ErrorAction Stop
                $assignedLicenses = $userDetail.assignedLicenses
                if (($assignedLicenses | Measure-Object).Count -gt 0) {
                    # User has productivity license AND admin role — dual-purpose account
                    $dualPurposeAdmins.Add("$($userDetail.displayName) ($($userDetail.userPrincipalName))")
                }
            }
            catch {
                Write-Verbose "Could not check licenses for admin $adminId: $_"
            }
        }

        $count = $dualPurposeAdmins.Count

        if ($count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$count admin account(s) have both privileged role assignments AND productivity licenses, suggesting they are dual-purpose (email + admin). This increases the phishing risk for privileged accounts."
        }
        else {
            $status = 'PASS'
            $detail = 'No privileged accounts with productivity licenses detected. Admin accounts appear to be dedicated cloud-only accounts.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ADM-001' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin accounts dedicated (separate from daily-use)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create separate cloud-only admin accounts (e.g. adm-firstname@tenant.onmicrosoft.com) without email or productivity licenses. Use daily-use accounts for email and collaboration. This limits the blast radius of phishing attacks targeting admin credentials.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices#3-use-privileged-access-workstations' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $dualPurposeAdmins.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ADM-001' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin accounts dedicated (separate from daily-use)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All, User.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All and User.Read.All permissions.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ADM-002: Admin account naming convention
    # -------------------------------------------------------------------------
    try {
        $allPrivUsers = Get-AllPrivilegedUsers
        $uniqueAdmins = $allPrivUsers | Sort-Object -Property principalId -Unique

        $noConventionAdmins = [System.Collections.Generic.List[string]]::new()
        $adminNamingPattern = '(?i)(^adm[-_.]|[-_.]adm@|^admin[-_.]|[-_.]admin@|\.adm@|^priv[-_.])'

        foreach ($admin in $uniqueAdmins) {
            $upn = $admin.principal.userPrincipalName
            if ($upn -and $upn -notmatch $adminNamingPattern) {
                $noConventionAdmins.Add("$($admin.principal.displayName) ($upn)")
            }
        }

        $total  = ($uniqueAdmins | Measure-Object).Count
        $noConvCount = $noConventionAdmins.Count

        if ($total -eq 0) {
            $status = 'INFO'
            $detail = 'No privileged accounts found to evaluate.'
        }
        elseif ($noConvCount -eq $total) {
            $status = 'LOW'
            $detail = "None of the $total admin account(s) follow an identifiable naming convention (e.g. adm-firstname, admin.firstname). Without a convention, admin accounts are harder to identify in logs and access reviews."
        }
        elseif ($noConvCount -gt 0) {
            $status = 'LOW'
            $detail = "$noConvCount of $total admin account(s) do not follow a consistent naming convention."
        }
        else {
            $status = 'PASS'
            $detail = "All $total admin account(s) follow a recognisable naming convention."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ADM-002' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin account naming convention' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Adopt a consistent naming convention for admin accounts, e.g. adm-firstname.lastname@tenant.onmicrosoft.com. This enables quick identification in sign-in logs, access reviews, and CA policies.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $noConventionAdmins.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ADM-002' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin account naming convention' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ADM-003: Admin MFA method strength
    # -------------------------------------------------------------------------
    try {
        $gaMembers = Get-RoleMembers -RoleDefinitionId $gaRoleDefId

        # Weak MFA methods (phone SMS/voice)
        $weakMfaAdmins = [System.Collections.Generic.List[string]]::new()

        foreach ($admin in $gaMembers) {
            $userId = $admin.principal.id
            $upn    = $admin.principal.userPrincipalName
            $authUri = "https://graph.microsoft.com/v1.0/users/$userId/authentication/methods"
            try {
                $authResponse = Invoke-MgGraphRequest -Method GET -Uri $authUri -ErrorAction Stop
                $methods = $authResponse.value
                $odataTypes = $methods.'@odata.type'

                $hasStrongMfa = $odataTypes | Where-Object {
                    $_ -in @(
                        '#microsoft.graph.fido2AuthenticationMethod',
                        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                        '#microsoft.graph.x509CertificateAuthenticationMethod',
                        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
                    )
                }

                $hasWeakOnly = ($odataTypes -contains '#microsoft.graph.phoneAuthenticationMethod') -and (-not $hasStrongMfa)

                if ($hasWeakOnly) {
                    $weakMfaAdmins.Add("$($admin.principal.displayName) ($upn) — only phone (SMS/voice) registered")
                }
                elseif (-not $hasStrongMfa -and -not $hasWeakOnly) {
                    $registeredTypes = ($odataTypes | ForEach-Object { $_ -replace '#microsoft.graph.', '' }) -join ', '
                    $weakMfaAdmins.Add("$($admin.principal.displayName) ($upn) — no strong MFA registered (methods: $registeredTypes)")
                }
            }
            catch {
                Write-Verbose "Could not check auth methods for $upn: $_"
            }
        }

        if ($weakMfaAdmins.Count -gt 0) {
            $status = 'HIGH'
            $detail = "$($weakMfaAdmins.Count) Global Administrator(s) using weak MFA (SMS/voice only) or no MFA: $($weakMfaAdmins -join '; ')."
        }
        else {
            $status = 'PASS'
            $detail = 'All Global Administrators have strong MFA methods registered (Authenticator app, FIDO2, or certificate).'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ADM-003' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin MFA method strength' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Require phishing-resistant MFA (FIDO2 security key or certificate-based auth) for all admin accounts. SMS and voice are vulnerable to SIM-swapping. Enforce via a CA policy with Authentication Strength set to "Phishing-resistant MFA".' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -CISControl 'CIS M365 1.1.1' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $weakMfaAdmins.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ADM-003' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin MFA method strength' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All, UserAuthenticationMethod.Read.All. Error: $_" `
            -Recommendation 'Grant UserAuthenticationMethod.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-strengths' `
            -CISControl 'CIS M365 1.1.1' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ADM-004: Stale admin accounts (not signed in for 30+ days)
    # -------------------------------------------------------------------------
    try {
        $allPrivUsers = Get-AllPrivilegedUsers
        $uniqueAdminIds = $allPrivUsers | Select-Object -ExpandProperty principalId -Unique

        $staleAdmins = [System.Collections.Generic.List[string]]::new()
        $cutoff = (Get-Date).AddDays(-30)

        foreach ($adminId in $uniqueAdminIds) {
            $userUri = "https://graph.microsoft.com/beta/users/$adminId`?`$select=id,displayName,userPrincipalName,signInActivity"
            try {
                $userDetail = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop
                $lastSignIn = $userDetail.signInActivity.lastSignInDateTime

                if ($null -eq $lastSignIn) {
                    $staleAdmins.Add("$($userDetail.displayName) ($($userDetail.userPrincipalName)) — never signed in")
                }
                elseif ([datetime]$lastSignIn -lt $cutoff) {
                    $daysSince = ([datetime]::Now - [datetime]$lastSignIn).Days
                    $staleAdmins.Add("$($userDetail.displayName) ($($userDetail.userPrincipalName)) — last sign-in: $lastSignIn ($daysSince days ago)")
                }
            }
            catch {
                Write-Verbose "Could not get signInActivity for $adminId: $_"
            }
        }

        if ($staleAdmins.Count -gt 0) {
            $status = 'HIGH'
            $detail = "$($staleAdmins.Count) admin account(s) have not signed in for 30+ days: $($staleAdmins -join '; '). Stale admin accounts may represent forgotten or orphaned privileged accounts."
        }
        else {
            $status = 'PASS'
            $detail = 'All admin accounts show sign-in activity within the last 30 days.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ADM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin account last sign-in (stale accounts)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Investigate and remove or disable admin accounts that have not been used in 30+ days. Configure access reviews for all privileged roles to detect stale accounts quarterly.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $staleAdmins.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ADM-004' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin account last sign-in (stale accounts)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All, AuditLog.Read.All (signInActivity via beta). Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ADM-005: Global Admin count vs Security Reader / Security Admin (least privilege)
    # -------------------------------------------------------------------------
    try {
        $secReaderRoleDefId = '5d6b6bb7-de71-4623-b4af-96380a352509'

        $gaMembers       = Get-RoleMembers -RoleDefinitionId $gaRoleDefId
        $praMembers      = Get-RoleMembers -RoleDefinitionId $praRoleDefId
        $secAdminMembers = Get-RoleMembers -RoleDefinitionId $secAdminRoleDefId
        $secReaderMembers= Get-RoleMembers -RoleDefinitionId $secReaderRoleDefId

        $gaCount         = ($gaMembers       | Select-Object -ExpandProperty principalId -Unique | Measure-Object).Count
        $praCount        = ($praMembers      | Select-Object -ExpandProperty principalId -Unique | Measure-Object).Count
        $secAdminCount   = ($secAdminMembers | Select-Object -ExpandProperty principalId -Unique | Measure-Object).Count
        $secReaderCount  = ($secReaderMembers| Select-Object -ExpandProperty principalId -Unique | Measure-Object).Count

        $restrictedRolesCount = $praCount + $secAdminCount + $secReaderCount

        if ($gaCount -gt $restrictedRolesCount -and $gaCount -gt 3) {
            $status = 'HIGH'
            $detail = "Global Admin count ($gaCount) exceeds combined Privileged Role Admin + Security Admin + Security Reader count ($restrictedRolesCount). This suggests over-use of Global Admin instead of scoped roles."
        }
        elseif ($gaCount -gt 5) {
            $status = 'HIGH'
            $detail = "Global Admin count ($gaCount) is high. GA: $gaCount | Privileged Role Admin: $praCount | Security Admin: $secAdminCount | Security Reader: $secReaderCount."
        }
        else {
            $status = 'PASS'
            $detail = "GA: $gaCount | Privileged Role Admin: $praCount | Security Admin: $secAdminCount | Security Reader: $secReaderCount. Ratio appears reasonable."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ADM-005' `
            -Category 'PrivilegedAccess' `
            -Name 'Global Admin count vs scoped admin roles (least privilege)' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Replace Global Administrator assignments with least-privilege scoped roles where possible. Use Security Administrator for security tasks, Exchange Administrator for mail configuration, etc. Target <5 Global Admins.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl 'CIS M365 1.1.2' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ADM-005' `
            -Category 'PrivilegedAccess' `
            -Name 'Global Admin count vs scoped admin roles (least privilege)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl 'CIS M365 1.1.2' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ADM-006: Admin accounts with active mailboxes (attack surface)
    # -------------------------------------------------------------------------
    try {
        $gaMembers = Get-RoleMembers -RoleDefinitionId $gaRoleDefId
        $gaWithMailbox = [System.Collections.Generic.List[string]]::new()

        foreach ($admin in $gaMembers) {
            $adminId = $admin.principal.id
            $upn     = $admin.principal.userPrincipalName

            # Check for mailbox via Exchange-related license or proxyAddresses
            $userUri = "https://graph.microsoft.com/v1.0/users/$adminId`?`$select=id,displayName,userPrincipalName,mail,assignedLicenses,proxyAddresses"
            try {
                $userDetail = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop

                # Presence of mail and proxy addresses indicates a mailbox
                $hasMail           = -not [string]::IsNullOrEmpty($userDetail.mail)
                $hasProxyAddresses = ($userDetail.proxyAddresses | Measure-Object).Count -gt 0

                # Check for mailbox-enabling licenses
                $licenses = $userDetail.assignedLicenses
                $hasMailboxLicense = $false
                foreach ($lic in $licenses) {
                    # We'd need to resolve skuId to skuPartNumber via subscribedSkus
                    # For now, presence of any license on a GA account is the indicator
                    $hasMailboxLicense = $true
                    break
                }

                if ($hasMail -or $hasProxyAddresses) {
                    $gaWithMailbox.Add("$($userDetail.displayName) ($upn) — mail: $($userDetail.mail)")
                }
            }
            catch {
                Write-Verbose "Could not check mailbox for $upn: $_"
            }
        }

        if ($gaWithMailbox.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$($gaWithMailbox.Count) Global Administrator(s) have active mailboxes: $($gaWithMailbox -join '; '). Admin accounts with mailboxes are susceptible to phishing and business email compromise."
        }
        else {
            $status = 'PASS'
            $detail = 'No Global Administrators have active mailboxes. Admin accounts appear to be mailbox-free.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ADM-006' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin accounts with active mailboxes' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Dedicated admin accounts should not have active mailboxes or productivity licenses. A phishing email received by an admin account directly targets privileged credentials. Keep admin and daily-use accounts separate.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $gaWithMailbox.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ADM-006' `
            -Category 'PrivilegedAccess' `
            -Name 'Admin accounts with active mailboxes' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: RoleManagement.Read.All, User.Read.All. Error: $_" `
            -Recommendation 'Grant User.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
