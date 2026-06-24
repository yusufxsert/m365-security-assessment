#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests emergency access (break-glass) account configuration.

.DESCRIPTION
    Validates that emergency access accounts exist, are cloud-only, excluded
    from Conditional Access blocking policies, have no productivity licenses,
    are monitored for sign-in activity, and use strong authentication methods
    (FIDO2 / certificate-based auth) rather than standard MFA.

.NOTES
    Required Permissions:
        - RoleManagement.Read.All
        - User.Read.All
        - Policy.Read.All          (for CA policy exclusion check)
        - AuditLog.Read.All        (for sign-in monitoring)
        - UserAuthenticationMethod.Read.All

    License: Microsoft 365 E3 / E5
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
#>

function Test-BreakGlass {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Naming patterns typical for emergency access accounts
    $breakGlassPattern = '(?i)(breakglass|break[-_]?glass|emergency|bg[-_]|bg\d|emerg)'

    # Licensing SKUs that indicate a productivity account (not a break-glass)
    $productivitySkus = @(
        'ENTERPRISEPREMIUM',   # E5
        'ENTERPRISEPACK',      # E3
        'SPE_E5',              # M365 E5
        'SPE_E3',              # M365 E3
        'EXCHANGESTANDARD',    # Exchange Online Plan 1
        'EXCHANGEENTERPRISE'   # Exchange Online Plan 2
    )

    # -------------------------------------------------------------------------
    # Helper: Resolve Global Admin members once
    # -------------------------------------------------------------------------
    $gaRoleDefId   = '62e90394-69f5-4237-9190-012177145e10'
    $gaMembers     = $null
    $bgAccounts    = $null

    try {
        $gaMembersUri  = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$filter=roleDefinitionId eq '$gaRoleDefId'&`$expand=principal&`$top=999"
        $gaMembersResp = Invoke-MgGraphRequest -Method GET -Uri $gaMembersUri -ErrorAction Stop
        $gaMembers     = $gaMembersResp.value | Where-Object {
            $_.principal.'@odata.type' -eq '#microsoft.graph.user'
        }

        # Identify candidate break-glass accounts by name pattern
        $bgAccounts = $gaMembers | Where-Object {
            $upn  = $_.principal.userPrincipalName
            $name = $_.principal.displayName
            $upn -match $breakGlassPattern -or $name -match $breakGlassPattern
        }

        # Also collect all GA users for other checks
    }
    catch {
        # Soft-fail: individual checks will handle their own try/catch
        Write-Verbose "Could not load GA members: $_"
    }

    # -------------------------------------------------------------------------
    # BGA-001: Emergency access accounts exist
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $gaMembers) {
            throw 'Could not retrieve Global Administrator members.'
        }

        $bgCount = ($bgAccounts | Measure-Object).Count

        $affectedObjects = $bgAccounts | ForEach-Object {
            "$($_.principal.displayName) ($($_.principal.userPrincipalName))"
        }

        if ($bgCount -eq 0) {
            $status = 'CRITICAL'
            $detail = "No emergency access accounts identified among $($gaMembers.Count) Global Administrator(s). Looked for naming patterns: breakglass, break-glass, emergency, bg-, emerg."
        }
        elseif ($bgCount -eq 1) {
            $status = 'HIGH'
            $detail = "Only 1 emergency access account found: $($affectedObjects -join ', '). Microsoft recommends 2 break-glass accounts for resilience."
        }
        else {
            $status = 'PASS'
            $detail = "$bgCount emergency access account(s) identified: $($affectedObjects -join ', ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'BGA-001' `
            -Category 'PrivilegedAccess' `
            -Name 'Emergency access accounts exist' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create 2 cloud-only break-glass Global Administrator accounts with names matching the pattern (breakglass, emergency). Store credentials in a physical vault. Monitor sign-in events as alerts.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $affectedObjects))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'BGA-001' `
            -Category 'PrivilegedAccess' `
            -Name 'Emergency access accounts exist' `
            -Status 'CRITICAL' `
            -Detail "Could not determine break-glass status. Required: RoleManagement.Read.All, User.Read.All. Error: $_" `
            -Recommendation 'Grant required permissions and verify break-glass accounts exist.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # BGA-002: Break glass accounts are cloud-only (not synced from on-prem)
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $bgAccounts -or ($bgAccounts | Measure-Object).Count -eq 0) {
            throw 'No break-glass accounts identified – skipping cloud-only check.'
        }

        $syncedBgAccounts = [System.Collections.Generic.List[string]]::new()

        foreach ($bg in $bgAccounts) {
            $userId = $bg.principal.id
            $userUri = "https://graph.microsoft.com/v1.0/users/$userId`?`$select=id,displayName,userPrincipalName,onPremisesSyncEnabled"
            $userDetail = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop
            if ($userDetail.onPremisesSyncEnabled -eq $true) {
                $syncedBgAccounts.Add("$($userDetail.displayName) ($($userDetail.userPrincipalName))")
            }
        }

        if ($syncedBgAccounts.Count -gt 0) {
            $status = 'HIGH'
            $detail = "$($syncedBgAccounts.Count) break-glass account(s) are synced from on-premises AD: $($syncedBgAccounts -join ', '). An on-prem compromise would also compromise the break-glass account."
        }
        else {
            $status = 'PASS'
            $detail = 'All identified break-glass accounts are cloud-only (not synced from on-premises).'
        }

        $results.Add((New-CheckResult `
            -CheckId 'BGA-002' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts are cloud-only' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Break-glass accounts must be cloud-only accounts created directly in Entra ID. Never sync them from on-premises Active Directory, as an on-prem compromise would invalidate them.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $syncedBgAccounts.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'BGA-002' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts are cloud-only' `
            -Status 'INFO' `
            -Detail "Check skipped: no break-glass accounts identified or insufficient permissions. Error: $_" `
            -Recommendation 'Ensure break-glass accounts exist and grant User.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # BGA-003: Break-glass accounts not targeted by blocking CA policies
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $bgAccounts -or ($bgAccounts | Measure-Object).Count -eq 0) {
            throw 'No break-glass accounts identified – skipping CA exclusion check.'
        }

        $caUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999'
        $caResponse = Invoke-MgGraphRequest -Method GET -Uri $caUri -ErrorAction Stop
        $caPolicies = $caResponse.value

        # Blocking policies: grantControls is null (block) or block
        $blockPolicies = $caPolicies | Where-Object {
            $_.state -eq 'enabled' -and (
                $null -eq $_.grantControls -or
                $_.grantControls.operator -eq 'OR' -and $_.grantControls.builtInControls -contains 'block'
            )
        }

        $bgUserIds = $bgAccounts | ForEach-Object { $_.principal.id }
        $exposedBgAccounts = [System.Collections.Generic.List[string]]::new()

        foreach ($policy in $blockPolicies) {
            $excludedUsers  = $policy.conditions.users.excludeUsers
            $excludedGroups = $policy.conditions.users.excludeGroups
            $includedUsers  = $policy.conditions.users.includeUsers
            $includedGroups = $policy.conditions.users.includeGroups

            foreach ($bgId in $bgUserIds) {
                $bgName = ($bgAccounts | Where-Object { $_.principal.id -eq $bgId }).principal.displayName

                # If the policy targets all users or this specific break-glass user
                $isTargeted = ($includedUsers -contains 'All' -or $includedUsers -contains $bgId)
                $isExcluded = ($excludedUsers -contains $bgId)

                if ($isTargeted -and -not $isExcluded) {
                    $exposedBgAccounts.Add("$bgName → Policy: '$($policy.displayName)'")
                }
            }
        }

        if ($exposedBgAccounts.Count -gt 0) {
            $status = 'CRITICAL'
            $detail = "$($exposedBgAccounts.Count) break-glass account(s) are not excluded from CA blocking policies and could be locked out: $($exposedBgAccounts -join '; ')."
        }
        else {
            $status = 'PASS'
            $detail = 'All break-glass accounts are excluded from Conditional Access blocking policies.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'BGA-003' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts excluded from CA blocking policies' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Add both break-glass accounts to the exclusion list of every CA policy that uses block controls. Create a named group "Emergency Access Accounts" and exclude this group from all blocking CA policies.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa#emergency-access-accounts' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $exposedBgAccounts.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'BGA-003' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts excluded from CA blocking policies' `
            -Status 'INFO' `
            -Detail "Check skipped: no break-glass accounts identified or insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All permission and ensure break-glass accounts are identified.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa#emergency-access-accounts' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # BGA-004: Break-glass accounts have no assigned licenses
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $bgAccounts -or ($bgAccounts | Measure-Object).Count -eq 0) {
            throw 'No break-glass accounts identified – skipping license check.'
        }

        $licensedBgAccounts = [System.Collections.Generic.List[string]]::new()

        foreach ($bg in $bgAccounts) {
            $userId = $bg.principal.id
            $licUri = "https://graph.microsoft.com/v1.0/users/$userId/licenseDetails"
            try {
                $licResponse = Invoke-MgGraphRequest -Method GET -Uri $licUri -ErrorAction Stop
                $licenses = $licResponse.value

                $hasProdLicense = $licenses | Where-Object {
                    $skuPartNumber = $_.skuPartNumber
                    $productivitySkus | Where-Object { $skuPartNumber -like "*$_*" }
                }

                if ($licenses.Count -gt 0) {
                    $skuList = ($licenses.skuPartNumber) -join ', '
                    $licensedBgAccounts.Add("$($bg.principal.displayName) ($($bg.principal.userPrincipalName)) — SKUs: $skuList")
                }
            }
            catch {
                Write-Verbose "Could not check licenses for $($bg.principal.userPrincipalName): $_"
            }
        }

        if ($licensedBgAccounts.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$($licensedBgAccounts.Count) break-glass account(s) have assigned licenses: $($licensedBgAccounts -join '; '). Licensed accounts depend on license availability and increase attack surface."
        }
        else {
            $status = 'PASS'
            $detail = 'No productivity licenses assigned to break-glass accounts.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'BGA-004' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts have no assigned licenses' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Remove all product licenses from break-glass accounts. Break-glass Global Administrator access does not require any license and the account should have minimal features enabled.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $licensedBgAccounts.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'BGA-004' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts have no assigned licenses' `
            -Status 'INFO' `
            -Detail "Check skipped: no break-glass accounts identified or insufficient permissions. Error: $_" `
            -Recommendation 'Ensure break-glass accounts exist and grant User.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # BGA-005: Break-glass account sign-in monitoring (last 90 days) – INFO
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $bgAccounts -or ($bgAccounts | Measure-Object).Count -eq 0) {
            throw 'No break-glass accounts identified – skipping sign-in check.'
        }

        $cutoff = (Get-Date).AddDays(-90).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $signInSummary = [System.Collections.Generic.List[string]]::new()

        foreach ($bg in $bgAccounts) {
            $userId = $bg.principal.id
            $upn    = $bg.principal.userPrincipalName
            $signInUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=userId eq '$userId' and createdDateTime ge $cutoff&`$top=5&`$orderby=createdDateTime desc"
            try {
                $signInResponse = Invoke-MgGraphRequest -Method GET -Uri $signInUri -ErrorAction Stop
                $signIns = $signInResponse.value
                $signInCount = ($signIns | Measure-Object).Count

                if ($signInCount -gt 0) {
                    $lastSignIn = $signIns[0].createdDateTime
                    $signInSummary.Add("ALERT: $upn had $signInCount sign-in(s) in the last 90 days. Last: $lastSignIn")
                }
                else {
                    $signInSummary.Add("OK: $upn — no sign-ins in last 90 days.")
                }
            }
            catch {
                $signInSummary.Add("Could not retrieve sign-ins for $upn: $_")
            }
        }

        $results.Add((New-CheckResult `
            -CheckId 'BGA-005' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass account sign-in monitoring (last 90 days)' `
            -Status 'INFO' `
            -Detail ($signInSummary -join ' | ') `
            -Recommendation 'Configure a Sentinel/Defender alert that fires whenever a break-glass account signs in. Any sign-in event should trigger an immediate security investigation. Integrate with a SIEM or use Microsoft Entra workbooks for monitoring.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access#monitor-sign-in-activity' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $signInSummary.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'BGA-005' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass account sign-in monitoring (last 90 days)' `
            -Status 'INFO' `
            -Detail "Check skipped: no break-glass accounts identified or AuditLog.Read.All permission missing. Error: $_" `
            -Recommendation 'Grant AuditLog.Read.All and ensure break-glass accounts are identified.' `
            -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access#monitor-sign-in-activity' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # BGA-006: Break-glass accounts using FIDO2 / cert-based auth
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $bgAccounts -or ($bgAccounts | Measure-Object).Count -eq 0) {
            throw 'No break-glass accounts identified – skipping auth method check.'
        }

        $weakAuthBgAccounts = [System.Collections.Generic.List[string]]::new()
        $strongAuthTypes = @(
            '#microsoft.graph.fido2AuthenticationMethod',
            '#microsoft.graph.x509CertificateAuthenticationMethod',
            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
        )

        foreach ($bg in $bgAccounts) {
            $userId = $bg.principal.id
            $upn    = $bg.principal.userPrincipalName
            $authUri = "https://graph.microsoft.com/v1.0/users/$userId/authentication/methods"
            try {
                $authResponse = Invoke-MgGraphRequest -Method GET -Uri $authUri -ErrorAction Stop
                $methods = $authResponse.value
                $odataTypes = $methods.'@odata.type'

                $hasStrongAuth = $methods | Where-Object {
                    $strongAuthTypes -contains $_.'@odata.type'
                }

                # Check for SMS / voice (weak)
                $hasWeakAuth = $methods | Where-Object {
                    $_.'@odata.type' -in @(
                        '#microsoft.graph.phoneAuthenticationMethod'
                    )
                }

                if (-not $hasStrongAuth) {
                    $registeredTypes = ($methods.'@odata.type' | ForEach-Object { $_ -replace '#microsoft.graph.', '' }) -join ', '
                    $weakAuthBgAccounts.Add("$upn — Registered methods: $registeredTypes")
                }
            }
            catch {
                Write-Verbose "Could not check auth methods for $upn: $_"
                $weakAuthBgAccounts.Add("$upn — Could not verify auth methods: $_")
            }
        }

        if ($weakAuthBgAccounts.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$($weakAuthBgAccounts.Count) break-glass account(s) are not using FIDO2 or certificate-based authentication: $($weakAuthBgAccounts -join '; ')."
        }
        else {
            $status = 'PASS'
            $detail = 'All break-glass accounts are using FIDO2 or certificate-based authentication.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'BGA-006' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts using FIDO2 / cert-based auth' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Register FIDO2 security keys (e.g. YubiKey) or x.509 certificates on break-glass accounts. Store one key per account in separate physical locations. Avoid SMS/voice MFA and TOTP apps for break-glass — the key/cert should be the authentication factor.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-passwordless-security-key' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $weakAuthBgAccounts.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'BGA-006' `
            -Category 'PrivilegedAccess' `
            -Name 'Break-glass accounts using FIDO2 / cert-based auth' `
            -Status 'INFO' `
            -Detail "Check skipped: no break-glass accounts identified or UserAuthenticationMethod.Read.All permission missing. Error: $_" `
            -Recommendation 'Grant UserAuthenticationMethod.Read.All and ensure break-glass accounts are identified.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-passwordless-security-key' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
