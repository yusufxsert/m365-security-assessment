#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Validates Identity Protection risk policies configuration and enforcement mode.

.DESCRIPTION
    Test-RiskPolicies checks whether the tenant has configured and enforced:
      - User risk policies (RPL-001)
      - Sign-in risk policies (RPL-002)
      - MFA registration policy (RPL-003)
      - Risk policies in enforcement vs. audit-only mode (RPL-004)

    Checks the modern CA-based risk policies first (v1.0 endpoint), then falls back
    to the legacy Identity Protection policy endpoints (beta) for older tenant configurations.
    All checks gracefully handle 403/license errors (Entra ID P2 required).

.NOTES
    Required Graph Permissions : Policy.Read.All, IdentityRiskyUser.Read.All
    License Required            : E5 / Entra ID P2 for all risk policy checks
    API Versions                : v1.0 (CA policies), beta (legacy risk policy endpoints)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-RiskPolicies {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Helper: detect E5 / license-related errors
    # -------------------------------------------------------------------------
    $isLicenseError = {
        param([string]$errorMessage)
        $errorMessage -match '(403|Forbidden|LicenseValidationFailed|AadPremiumLicenseRequired|Unauthorized|premium)'
    }

    # -------------------------------------------------------------------------
    # Retrieve CA policies once (needed for RPL-001, RPL-002, RPL-004)
    # -------------------------------------------------------------------------
    $caPolicies      = $null
    $caFetchError    = $null
    try {
        $caPolicyResponse = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250' `
            -ErrorAction Stop
        $caPolicies = $caPolicyResponse.value

        $nextLink = $caPolicyResponse.'@odata.nextLink'
        while ($nextLink) {
            $page       = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $caPolicies += $page.value
            $nextLink   = $page.'@odata.nextLink'
        }
    }
    catch {
        $caFetchError = $_.ToString()
    }

    # =========================================================================
    # RPL-001: User risk policy configured and in enforcement
    # =========================================================================
    if ($caFetchError) {
        $rpl001Status = 'INFO'
        $rpl001Detail = "Check skipped: could not retrieve CA policies. Error: $caFetchError"
        $userRiskPoliciesEnabled = @()
    }
    else {
        # Modern: CA policy with userRiskLevels condition
        $userRiskPolicies        = @($caPolicies | Where-Object { $_.conditions.userRiskLevels.Count -gt 0 })
        $userRiskPoliciesEnabled = @($userRiskPolicies | Where-Object { $_.state -eq 'enabled' })
        $userRiskPoliciesRO      = @($userRiskPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

        # Check that at least one enforced policy acts on high risk
        $highRiskActed = @($userRiskPoliciesEnabled | Where-Object {
            $_.conditions.userRiskLevels -contains 'high' -and
            ($_.grantControls.builtInControls -contains 'block' -or
             $_.grantControls.builtInControls -contains 'passwordChange' -or
             $_.grantControls.builtInControls -contains 'mfa' -or
             $_.grantControls.authenticationStrength -ne $null)
        })

        if ($highRiskActed.Count -gt 0) {
            $rpl001Status = 'PASS'
            $rpl001Detail = "User risk policy (CA-based): $($userRiskPoliciesEnabled.Count) enabled, $($userRiskPoliciesRO.Count) report-only. " +
                            "Policies acting on high user risk: $($highRiskActed.Count)."
        }
        elseif ($userRiskPoliciesRO.Count -gt 0) {
            # Legacy beta endpoint as fallback
            try {
                $legacyURPolicy = Invoke-MgGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/beta/identityProtection/policies/userRiskPolicy' `
                    -ErrorAction Stop
                $legacyEnabled  = $legacyURPolicy.state -eq 'enabled'
                $rpl001Status   = if ($legacyEnabled) { 'HIGH' } else { 'HIGH' }
                $rpl001Detail   = "CA user risk policies are report-only only. Legacy user risk policy state: $($legacyURPolicy.state). " +
                                  "Policy is not enforcing — high-risk users face no access restriction."
            }
            catch {
                $rpl001Status = 'HIGH'
                $rpl001Detail = "User risk CA policies are report-only ($($userRiskPoliciesRO.Count)). No enforced user risk policy found. Error reading legacy policy: $_"
            }
        }
        else {
            $rpl001Status = 'HIGH'
            $rpl001Detail = "No CA policies with userRiskLevels condition found (enabled or report-only). " +
                            "High-risk users (leaked creds, confirmed compromise) have no automated access gate."
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RPL-001' `
        -Category 'IdentityProtection' `
        -Name 'User Risk Policy Configured and Enforced' `
        -Status $rpl001Status `
        -Detail $rpl001Detail `
        -Recommendation 'Create an enabled CA policy: All users → All cloud apps → User risk: High → Block or require password change. Do not leave in report-only mode.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
        -CISControl '' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # =========================================================================
    # RPL-002: Sign-in risk policy configured and in enforcement
    # =========================================================================
    if ($caFetchError) {
        $rpl002Status = 'INFO'
        $rpl002Detail = "Check skipped: could not retrieve CA policies. Error: $caFetchError"
        $signInRiskEnabled = @()
    }
    else {
        $signInRiskPolicies  = @($caPolicies | Where-Object { $_.conditions.signInRiskLevels.Count -gt 0 })
        $signInRiskEnabled   = @($signInRiskPolicies | Where-Object { $_.state -eq 'enabled' })
        $signInRiskRO        = @($signInRiskPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

        $highSignInActed = @($signInRiskEnabled | Where-Object {
            $_.conditions.signInRiskLevels -contains 'high' -and
            ($_.grantControls.builtInControls -contains 'block' -or
             $_.grantControls.builtInControls -contains 'mfa' -or
             $_.grantControls.authenticationStrength -ne $null)
        })

        if ($highSignInActed.Count -gt 0) {
            $rpl002Status = 'PASS'
            $rpl002Detail = "Sign-in risk policy (CA-based): $($signInRiskEnabled.Count) enabled, $($signInRiskRO.Count) report-only. " +
                            "Policies acting on high sign-in risk: $($highSignInActed.Count)."
        }
        elseif ($signInRiskRO.Count -gt 0) {
            $rpl002Status = 'HIGH'
            $rpl002Detail = "Sign-in risk CA policies exist but are report-only ($($signInRiskRO.Count)). No enforcement active — high-risk sign-ins (anomalous token, impossible travel) proceed freely."
        }
        else {
            $rpl002Status = 'HIGH'
            $rpl002Detail = "No CA policies with signInRiskLevels condition found. High-risk sign-ins have no automated response."
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RPL-002' `
        -Category 'IdentityProtection' `
        -Name 'Sign-In Risk Policy Configured and Enforced' `
        -Status $rpl002Status `
        -Detail $rpl002Detail `
        -Recommendation 'Create an enabled CA policy: All users → All cloud apps → Sign-in risk: High → Block or require MFA. Consider also requiring MFA for medium risk.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
        -CISControl '' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # =========================================================================
    # RPL-003: MFA registration policy
    # =========================================================================
    try {
        $mfaRegPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/identityProtection/policies/multifactorAuthenticationRegistrationPolicy' `
            -ErrorAction Stop

        $policyState  = $mfaRegPolicy.state          # enabled | disabled
        $includeAll   = $mfaRegPolicy.includedUsers -contains 'all' -or
                        $mfaRegPolicy.includedGroups.Count -eq 0  # no group restriction = all users
        $excludedCount = @($mfaRegPolicy.excludedUsers + $mfaRegPolicy.excludedGroups).Count

        if ($policyState -eq 'enabled' -and $includeAll) {
            $rpl003Status = 'PASS'
            $rpl003Detail = "MFA registration policy is enabled and targets all users. Excluded objects: $excludedCount."
        }
        elseif ($policyState -eq 'enabled') {
            $rpl003Status = 'MEDIUM'
            $rpl003Detail = "MFA registration policy is enabled but scoped to specific groups (not all users). Excluded objects: $excludedCount. Some users may not be prompted to register MFA."
        }
        else {
            $rpl003Status = 'MEDIUM'
            $rpl003Detail = "MFA registration policy state: $policyState. Policy not enforcing MFA registration — users may skip registration indefinitely."
        }
    }
    catch {
        $errStr       = $_.ToString()
        $rpl003Status = 'INFO'
        $rpl003Detail = if (& $isLicenseError $errStr) {
            "Check skipped: Entra ID P2 license required for MFA registration policy. Error: $errStr"
        } else {
            "Check skipped: insufficient permissions or policy not configured. Required: Policy.Read.All. Error: $errStr"
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RPL-003' `
        -Category 'IdentityProtection' `
        -Name 'MFA Registration Policy' `
        -Status $rpl003Status `
        -Detail $rpl003Detail `
        -Recommendation 'Enable the MFA registration policy for all users in Entra ID Protection. This ensures users register MFA methods before being subject to risk-based MFA challenges.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-mfa-policy' `
        -CISControl '' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # =========================================================================
    # RPL-004: Risk policies in enforcement vs. audit-only mode
    # =========================================================================
    if ($caFetchError) {
        $rpl004Status = 'INFO'
        $rpl004Detail = "Check skipped: could not retrieve CA policies. Error: $caFetchError"
    }
    else {
        $allRiskPolicies     = @($caPolicies | Where-Object {
            $_.conditions.userRiskLevels.Count -gt 0 -or $_.conditions.signInRiskLevels.Count -gt 0
        })
        $enforced            = @($allRiskPolicies | Where-Object { $_.state -eq 'enabled' })
        $auditOnly           = @($allRiskPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })
        $auditOnlyNames      = @($auditOnly | ForEach-Object { $_.displayName })

        if ($allRiskPolicies.Count -eq 0) {
            $rpl004Status = 'HIGH'
            $rpl004Detail = 'No risk-based CA policies found at all (neither enforced nor audit mode).'
        }
        elseif ($enforced.Count -eq 0 -and $auditOnly.Count -gt 0) {
            $rpl004Status = 'HIGH'
            $rpl004Detail = "All $($auditOnly.Count) risk-based CA policies are in audit/report-only mode — no enforcement active. " +
                            "Policies: $($auditOnlyNames -join '; ')"
        }
        elseif ($auditOnly.Count -gt 0) {
            $rpl004Status = 'MEDIUM'
            $rpl004Detail = "Risk-based CA policies: $($enforced.Count) enforced, $($auditOnly.Count) audit-only. " +
                            "Audit-only policies (not enforcing): $($auditOnlyNames -join '; ')"
        }
        else {
            $rpl004Status = 'PASS'
            $rpl004Detail = "All $($enforced.Count) risk-based CA policies are in enforced mode. No audit-only risk policies detected."
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RPL-004' `
        -Category 'IdentityProtection' `
        -Name 'Risk Policies — Enforcement vs. Audit Mode' `
        -Status $rpl004Status `
        -Detail $rpl004Detail `
        -Recommendation 'Move risk-based CA policies from report-only to enabled enforcement. Start with report-only during testing, then switch to enabled once confident in exclusions and scope.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only' `
        -CISControl '' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects @($auditOnly | ForEach-Object { $_.displayName })))

    return $results
}
