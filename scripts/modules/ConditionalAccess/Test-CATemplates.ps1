#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Validates Conditional Access policies against Microsoft, CISA SCuBA, and CIS benchmarks.

.DESCRIPTION
    Test-CATemplates checks whether the tenant's enabled CA policies satisfy the controls
    mandated by:
      - Microsoft's recommended baseline templates (TPL-001)
      - CISA M365 Security Configuration Baseline for Azure AD / SCuBA (TPL-002)
      - CIS Microsoft 365 Foundations Benchmark (TPL-003)

    Each control produces a PASS or a finding at the severity level defined by the framework.
    The function never modifies tenant configuration.

.NOTES
    Required Graph Permissions : Policy.Read.All
    License Required            : E3; controls referencing risk require E5
    References:
      Microsoft Baseline  — https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access
      CISA SCuBA          — https://www.cisa.gov/sites/default/files/2024-01/microsoft_365_secure_configuration_baseline_for_aad_v1_0_0.pdf
      CIS M365 Benchmark  — https://www.cisecurity.org/benchmark/microsoft_365

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/ConditionalAccess/Test-CATemplates.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-CATemplates {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all CA policies once
    # -------------------------------------------------------------------------
    try {
        $policiesResponse = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250' `
            -ErrorAction Stop
        $allPolicies = $policiesResponse.value

        $nextLink = $policiesResponse.'@odata.nextLink'
        while ($nextLink) {
            $page        = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $allPolicies += $page.value
            $nextLink    = $page.'@odata.nextLink'
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'TPL-000' `
            -Category 'ConditionalAccess' `
            -Name 'CA Template Alignment — Policy Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access' `
            -CISControl '' `
            -SC300Domain 'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $enabled = @($allPolicies | Where-Object { $_.state -eq 'enabled' })

    # -------------------------------------------------------------------------
    # Shared helper closures
    # -------------------------------------------------------------------------
    $hasMfa = {
        param($policy)
        $policy.grantControls.builtInControls -contains 'mfa' -or
        $policy.grantControls.authenticationStrength -ne $null
    }

    $hasBlock = {
        param($policy)
        $policy.grantControls.builtInControls -contains 'block'
    }

    # Check if any enabled policy satisfies a predicate
    $anyEnabled = {
        param([scriptblock]$predicate)
        ($enabled | Where-Object { & $predicate $_ }).Count -gt 0
    }

    # =========================================================================
    # TPL-001: Microsoft-Recommended Baseline Templates
    # =========================================================================

    # --- Template 1: Require MFA for admins ---
    $t1 = & $anyEnabled { param($p)
        $p.conditions.users.includeRoles.Count -gt 0 -and (& $hasMfa $p)
    }
    $results.Add((New-CheckResult `
        -CheckId 'TPL-001-T1' `
        -Category 'ConditionalAccess' `
        -Name 'MS Baseline: Require MFA for Admins' `
        -Status $(if ($t1) { 'PASS' } else { 'HIGH' }) `
        -Detail $(if ($t1) {
            'PASS — At least one enabled policy requires MFA for directory roles.'
        } else {
            'MISSING — No enabled CA policy requires MFA for admin roles. Microsoft baseline template not implemented.'
        }) `
        -Recommendation 'Implement Microsoft baseline: Require multifactor authentication for admins. Target all privileged roles.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa' `
        -CISControl 'CIS M365 1.2.1' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # --- Template 2: Require MFA for Azure management ---
    $azureManagementId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
    $t2 = & $anyEnabled { param($p)
        ($p.conditions.applications.includeApplications -contains $azureManagementId -or
         $p.conditions.applications.includeApplications -contains 'All') -and
        (& $hasMfa $p)
    }
    $results.Add((New-CheckResult `
        -CheckId 'TPL-001-T2' `
        -Category 'ConditionalAccess' `
        -Name 'MS Baseline: Require MFA for Azure Management' `
        -Status $(if ($t2) { 'PASS' } else { 'HIGH' }) `
        -Detail $(if ($t2) {
            'PASS — Azure management access is protected by MFA via CA policy.'
        } else {
            "MISSING — No enabled CA policy requires MFA for Azure Management (appId: $azureManagementId)."
        }) `
        -Recommendation 'Implement Microsoft baseline: Require MFA for Azure management. Target app ID 797f4846-ba00-4fd7-ba43-dac1f8f63013.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # --- Template 3: Block legacy authentication ---
    $t3 = & $anyEnabled { param($p)
        ($p.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
         $p.conditions.clientAppTypes -contains 'other') -and
        (& $hasBlock $p)
    }
    $results.Add((New-CheckResult `
        -CheckId 'TPL-001-T3' `
        -Category 'ConditionalAccess' `
        -Name 'MS Baseline: Block Legacy Authentication' `
        -Status $(if ($t3) { 'PASS' } else { 'CRITICAL' }) `
        -Detail $(if ($t3) {
            'PASS — Legacy authentication is blocked by an enabled CA policy.'
        } else {
            'MISSING — No enabled CA policy blocks legacy client app types (EAS/other). Critical Microsoft baseline control not met.'
        }) `
        -Recommendation 'Implement Microsoft baseline: Block legacy authentication. Target clientAppTypes: exchangeActiveSync, other → Block.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
        -CISControl 'CIS M365 1.2.3' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # --- Template 4: Require MFA for all users ---
    $t4 = & $anyEnabled { param($p)
        $p.conditions.users.includeUsers -contains 'All' -and (& $hasMfa $p)
    }
    $results.Add((New-CheckResult `
        -CheckId 'TPL-001-T4' `
        -Category 'ConditionalAccess' `
        -Name 'MS Baseline: Require MFA for All Users' `
        -Status $(if ($t4) { 'PASS' } else { 'CRITICAL' }) `
        -Detail $(if ($t4) {
            'PASS — All users are covered by an enabled MFA CA policy.'
        } else {
            'MISSING — No enabled CA policy requires MFA for All users. This is a foundational Microsoft baseline control.'
        }) `
        -Recommendation 'Implement Microsoft baseline: Require MFA for all users (exclude break-glass accounts via group exclusion).' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa' `
        -CISControl 'CIS M365 1.2.2' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # --- Template 5: Require compliant device for Windows ---
    $t5 = & $anyEnabled { param($p)
        ($p.conditions.platforms.includePlatforms -contains 'windows' -or
         $p.conditions.platforms.includePlatforms.Count -eq 0) -and
        ($p.grantControls.builtInControls -contains 'compliantDevice' -or
         $p.grantControls.builtInControls -contains 'domainJoinedDevice')
    }
    $results.Add((New-CheckResult `
        -CheckId 'TPL-001-T5' `
        -Category 'ConditionalAccess' `
        -Name 'MS Baseline: Require Compliant Device for Windows' `
        -Status $(if ($t5) { 'PASS' } else { 'HIGH' }) `
        -Detail $(if ($t5) {
            'PASS — Windows device compliance or Hybrid Join is required by an enabled CA policy.'
        } else {
            'MISSING — No enabled CA policy requires compliant or Hybrid Azure AD joined Windows devices.'
        }) `
        -Recommendation 'Implement Microsoft baseline: Require compliant device for Windows (platform filter) → compliantDevice or domainJoinedDevice grant control.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # =========================================================================
    # TPL-002: CISA SCuBA — M365 Azure AD Security Configuration Baseline
    # =========================================================================

    # MS.AAD.3.1 — Block legacy authentication
    $scuba31 = $t3   # Same check as TPL-001-T3
    $results.Add((New-CheckResult `
        -CheckId 'TPL-002-MS.AAD.3.1' `
        -Category 'ConditionalAccess' `
        -Name 'SCuBA MS.AAD.3.1: Legacy Auth Blocked' `
        -Status $(if ($scuba31) { 'PASS' } else { 'CRITICAL' }) `
        -Detail $(if ($scuba31) {
            'PASS — MS.AAD.3.1 satisfied: Legacy authentication is blocked.'
        } else {
            'FAIL — MS.AAD.3.1: Legacy authentication is NOT blocked. CISA SCuBA requires this control as Critical.'
        }) `
        -Recommendation 'CISA SCuBA MS.AAD.3.1: Block legacy authentication protocols via Conditional Access.' `
        -Reference 'https://www.cisa.gov/sites/default/files/2024-01/microsoft_365_secure_configuration_baseline_for_aad_v1_0_0.pdf' `
        -CISControl 'CIS M365 1.2.3' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # MS.AAD.3.2 — High-risk users blocked (E5)
    $scuba32 = & $anyEnabled { param($p)
        $p.conditions.userRiskLevels -contains 'high' -and
        ($p.grantControls.builtInControls -contains 'block' -or
         $p.grantControls.builtInControls -contains 'passwordChange' -or
         (& $hasMfa $p))
    }
    $results.Add((New-CheckResult `
        -CheckId 'TPL-002-MS.AAD.3.2' `
        -Category 'ConditionalAccess' `
        -Name 'SCuBA MS.AAD.3.2: High-Risk Users Blocked' `
        -Status $(if ($scuba32) { 'PASS' } else { 'HIGH' }) `
        -Detail $(if ($scuba32) {
            'PASS — MS.AAD.3.2 satisfied: High-risk users are subject to a CA policy action.'
        } else {
            'FAIL — MS.AAD.3.2: No CA policy acts on high user risk. Requires Entra ID P2 (E5).'
        }) `
        -Recommendation 'CISA SCuBA MS.AAD.3.2: Create a CA policy blocking or requiring password change for high user risk.' `
        -Reference 'https://www.cisa.gov/sites/default/files/2024-01/microsoft_365_secure_configuration_baseline_for_aad_v1_0_0.pdf' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # MS.AAD.3.3 — High-risk sign-ins blocked (E5)
    $scuba33 = & $anyEnabled { param($p)
        $p.conditions.signInRiskLevels -contains 'high' -and
        ($p.grantControls.builtInControls -contains 'block' -or (& $hasMfa $p))
    }
    $results.Add((New-CheckResult `
        -CheckId 'TPL-002-MS.AAD.3.3' `
        -Category 'ConditionalAccess' `
        -Name 'SCuBA MS.AAD.3.3: High-Risk Sign-Ins Blocked' `
        -Status $(if ($scuba33) { 'PASS' } else { 'HIGH' }) `
        -Detail $(if ($scuba33) {
            'PASS — MS.AAD.3.3 satisfied: High-risk sign-ins trigger a CA policy action.'
        } else {
            'FAIL — MS.AAD.3.3: No CA policy acts on high sign-in risk. Requires Entra ID P2 (E5).'
        }) `
        -Recommendation 'CISA SCuBA MS.AAD.3.3: Create a CA policy blocking or requiring MFA for high sign-in risk.' `
        -Reference 'https://www.cisa.gov/sites/default/files/2024-01/microsoft_365_secure_configuration_baseline_for_aad_v1_0_0.pdf' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # MS.AAD.3.4 — MFA for all users
    $scuba34 = $t4
    $results.Add((New-CheckResult `
        -CheckId 'TPL-002-MS.AAD.3.4' `
        -Category 'ConditionalAccess' `
        -Name 'SCuBA MS.AAD.3.4: MFA for All Users' `
        -Status $(if ($scuba34) { 'PASS' } else { 'CRITICAL' }) `
        -Detail $(if ($scuba34) {
            'PASS — MS.AAD.3.4 satisfied: All users are required to use MFA.'
        } else {
            'FAIL — MS.AAD.3.4: No CA policy enforces MFA for all users. CISA SCuBA Critical control not met.'
        }) `
        -Recommendation 'CISA SCuBA MS.AAD.3.4: Require MFA for all users via Conditional Access.' `
        -Reference 'https://www.cisa.gov/sites/default/files/2024-01/microsoft_365_secure_configuration_baseline_for_aad_v1_0_0.pdf' `
        -CISControl 'CIS M365 1.2.2' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # MS.AAD.3.5 — MFA for admins
    $scuba35 = $t1
    $results.Add((New-CheckResult `
        -CheckId 'TPL-002-MS.AAD.3.5' `
        -Category 'ConditionalAccess' `
        -Name 'SCuBA MS.AAD.3.5: MFA for Admins' `
        -Status $(if ($scuba35) { 'PASS' } else { 'CRITICAL' }) `
        -Detail $(if ($scuba35) {
            'PASS — MS.AAD.3.5 satisfied: Admin roles are required to use MFA.'
        } else {
            'FAIL — MS.AAD.3.5: No CA policy enforces MFA for admin roles. CISA SCuBA Critical control not met.'
        }) `
        -Recommendation 'CISA SCuBA MS.AAD.3.5: Require phishing-resistant MFA for all privileged roles.' `
        -Reference 'https://www.cisa.gov/sites/default/files/2024-01/microsoft_365_secure_configuration_baseline_for_aad_v1_0_0.pdf' `
        -CISControl 'CIS M365 1.2.1' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # MS.AAD.3.6 — Device compliance for corporate access
    $scuba36 = $t5
    $results.Add((New-CheckResult `
        -CheckId 'TPL-002-MS.AAD.3.6' `
        -Category 'ConditionalAccess' `
        -Name 'SCuBA MS.AAD.3.6: Device Compliance for Corporate Access' `
        -Status $(if ($scuba36) { 'PASS' } else { 'HIGH' }) `
        -Detail $(if ($scuba36) {
            'PASS — MS.AAD.3.6 satisfied: Device compliance is required by a CA policy.'
        } else {
            'FAIL — MS.AAD.3.6: No CA policy requires device compliance or domain join for corporate access.'
        }) `
        -Recommendation 'CISA SCuBA MS.AAD.3.6: Require managed/compliant devices for accessing corporate resources.' `
        -Reference 'https://www.cisa.gov/sites/default/files/2024-01/microsoft_365_secure_configuration_baseline_for_aad_v1_0_0.pdf' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # =========================================================================
    # TPL-003: CIS Microsoft 365 Foundations Benchmark
    # =========================================================================

    # CIS 1.1.3 — MFA for privileged users
    $cis113 = $t1
    $results.Add((New-CheckResult `
        -CheckId 'TPL-003-CIS1.1.3' `
        -Category 'ConditionalAccess' `
        -Name 'CIS 1.1.3: MFA for Privileged Users' `
        -Status $(if ($cis113) { 'PASS' } else { 'CRITICAL' }) `
        -Detail $(if ($cis113) {
            'PASS — CIS 1.1.3 satisfied: MFA is enforced for privileged (role-targeted) users.'
        } else {
            'FAIL — CIS 1.1.3: No CA policy enforces MFA for privileged users. CIS Critical control not met.'
        }) `
        -Recommendation 'CIS M365 1.1.3: Ensure MFA is enabled for all users in privileged roles via Conditional Access.' `
        -Reference 'https://www.cisecurity.org/benchmark/microsoft_365' `
        -CISControl 'CIS M365 1.1.3' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # CIS 1.2.1 — Block legacy authentication
    $cis121 = $t3
    $results.Add((New-CheckResult `
        -CheckId 'TPL-003-CIS1.2.1' `
        -Category 'ConditionalAccess' `
        -Name 'CIS 1.2.1: Block Legacy Authentication' `
        -Status $(if ($cis121) { 'PASS' } else { 'CRITICAL' }) `
        -Detail $(if ($cis121) {
            'PASS — CIS 1.2.1 satisfied: Legacy authentication protocols are blocked.'
        } else {
            'FAIL — CIS 1.2.1: Legacy authentication is not blocked. CIS Critical control not met.'
        }) `
        -Recommendation 'CIS M365 1.2.1: Ensure legacy authentication is blocked via Conditional Access policy targeting EAS and other client app types.' `
        -Reference 'https://www.cisecurity.org/benchmark/microsoft_365' `
        -CISControl 'CIS M365 1.2.1' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
