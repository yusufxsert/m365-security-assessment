#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Reports

<#
.SYNOPSIS
    Tests emergency access (break-glass) account configuration.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-Mg* cmdlets from Microsoft.Graph PowerShell SDK
    instead of Invoke-MgGraphRequest. Authentication is interactive delegated
    (Connect-MgGraph -Scopes "...") — no App Registration or service principal
    required. All check IDs, thresholds, and result logic are identical to the
    Graph-HTTP variant (modules/PrivilegedAccess/Test-BreakGlass.ps1).

    SEE ALSO: scripts/modules/PrivilegedAccess/Test-BreakGlass.ps1
              (Graph HTTP variant using Invoke-MgGraphRequest)

    Validates that emergency access accounts exist, are cloud-only, excluded
    from Conditional Access blocking policies, have no productivity licenses,
    are monitored for sign-in activity, and use strong authentication methods
    (FIDO2 / certificate-based auth) rather than standard MFA.

.NOTES
    WHY PS-ONLY
        Intended for interactive use by admins who connect with their own credentials.
        No service principal, no client secret, no certificate — just:
            Connect-MgGraph -Scopes "RoleManagement.Read.All","User.Read.All","Policy.Read.All","AuditLog.Read.All","UserAuthenticationMethod.Read.All"

    Required connection  : Connect-MgGraph (delegated, interactive)
    Required scopes      : RoleManagement.Read.All, User.Read.All, Policy.Read.All,
                           AuditLog.Read.All, UserAuthenticationMethod.Read.All
    Required module      : Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users,
                           Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Reports
    License              : Microsoft 365 E3 / E5
    CIS Benchmark        : CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain        : Identity Governance

    BGA-004 (license check) uses Get-MgUser -Property assignedLicenses instead of
    /licenseDetails so no additional module is needed.

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-BreakGlass {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $breakGlassPattern = '(?i)(breakglass|break[-_]?glass|emergency|bg[-_]|bg\d|emerg)'

    $productivitySkus = @(
        'ENTERPRISEPREMIUM',
        'ENTERPRISEPACK',
        'SPE_E5',
        'SPE_E3',
        'EXCHANGESTANDARD',
        'EXCHANGEENTERPRISE'
    )

    # -------------------------------------------------------------------------
    # Helper: Resolve Global Admin members once
    # -------------------------------------------------------------------------
    $gaRoleDefId = '62e90394-69f5-4237-9190-012177145e10'
    $gaMembers   = $null
    $bgAccounts  = $null

    try {
        $gaSchedules = Get-MgRoleManagementDirectoryRoleAssignmentSchedule -All `
            -Filter "roleDefinitionId eq '$gaRoleDefId'" `
            -ExpandProperty principal -ErrorAction Stop

        $gaMembers = $gaSchedules | Where-Object {
            $_.Principal.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user'
        }

        $bgAccounts = $gaMembers | Where-Object {
            $upn  = $_.Principal.AdditionalProperties.userPrincipalName
            $name = $_.Principal.AdditionalProperties.displayName
            $upn -match $breakGlassPattern -or $name -match $breakGlassPattern
        }
    }
    catch {
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
            "$($_.Principal.AdditionalProperties.displayName) ($($_.Principal.AdditionalProperties.userPrincipalName))"
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
            $userId     = $bg.PrincipalId
            $userDetail = Get-MgUser -UserId $userId `
                -Property 'id,displayName,userPrincipalName,onPremisesSyncEnabled' `
                -ErrorAction Stop
            if ($userDetail.OnPremisesSyncEnabled -eq $true) {
                $syncedBgAccounts.Add("$($userDetail.DisplayName) ($($userDetail.UserPrincipalName))")
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

        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        $blockPolicies = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and (
                $null -eq $_.GrantControls -or
                ($_.GrantControls.Operator -eq 'OR' -and $_.GrantControls.BuiltInControls -contains 'block')
            )
        }

        $bgUserIds           = $bgAccounts | ForEach-Object { $_.PrincipalId }
        $exposedBgAccounts   = [System.Collections.Generic.List[string]]::new()

        foreach ($policy in $blockPolicies) {
            $excludedUsers = $policy.Conditions.Users.ExcludeUsers
            $includedUsers = $policy.Conditions.Users.IncludeUsers

            foreach ($bgId in $bgUserIds) {
                $bgName     = ($bgAccounts | Where-Object { $_.PrincipalId -eq $bgId }).Principal.AdditionalProperties.displayName
                $isTargeted = ($includedUsers -contains 'All' -or $includedUsers -contains $bgId)
                $isExcluded = ($excludedUsers -contains $bgId)

                if ($isTargeted -and -not $isExcluded) {
                    $exposedBgAccounts.Add("$bgName → Policy: '$($policy.DisplayName)'")
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
            $userId = $bg.PrincipalId
            $upn    = $bg.Principal.AdditionalProperties.userPrincipalName
            try {
                $userDetail = Get-MgUser -UserId $userId -Property 'id,displayName,userPrincipalName,assignedLicenses' -ErrorAction Stop
                $licenses   = $userDetail.AssignedLicenses

                if (($licenses | Measure-Object).Count -gt 0) {
                    # Resolve skuPartNumber via assignedLicenses.skuId — we report the skuIds
                    # since full resolution needs Get-MgSubscribedSku (not in scope here)
                    $skuIds = ($licenses.SkuId) -join ', '
                    $licensedBgAccounts.Add("$($bg.Principal.AdditionalProperties.displayName) ($upn) — skuIds: $skuIds")
                }
            }
            catch {
                Write-Verbose "Could not check licenses for $upn: $_"
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

        $signInSummary = [System.Collections.Generic.List[string]]::new()

        foreach ($bg in $bgAccounts) {
            $userId = $bg.PrincipalId
            $upn    = $bg.Principal.AdditionalProperties.userPrincipalName
            try {
                # Get-MgAuditLogSignIn supports OData $filter; -Top limits results.
                $signIn = Get-MgAuditLogSignIn -Filter "userId eq '$userId'" -Top 1 -ErrorAction Stop

                if ($signIn) {
                    $lastSignIn = $signIn.CreatedDateTime
                    $signInSummary.Add("ALERT: $upn — last sign-in: $lastSignIn")
                }
                else {
                    $signInSummary.Add("OK: $upn — no sign-in records found in audit log.")
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
        $strongAuthTypes    = @(
            '#microsoft.graph.fido2AuthenticationMethod',
            '#microsoft.graph.x509CertificateAuthenticationMethod',
            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
        )

        foreach ($bg in $bgAccounts) {
            $userId = $bg.PrincipalId
            $upn    = $bg.Principal.AdditionalProperties.userPrincipalName
            try {
                $methods = Get-MgUserAuthenticationMethod -UserId $userId -All -ErrorAction Stop

                $hasStrongAuth = $methods | Where-Object {
                    $strongAuthTypes -contains $_.AdditionalProperties.'@odata.type'
                }

                if (-not $hasStrongAuth) {
                    $registeredTypes = ($methods | ForEach-Object {
                        $_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
                    }) -join ', '
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
