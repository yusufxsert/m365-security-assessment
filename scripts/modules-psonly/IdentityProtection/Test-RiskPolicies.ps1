#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Audits Conditional Access risk policies and Identity Protection policy configuration. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgIdentityConditionalAccessPolicy -All to detect
    risk-based Conditional Access policies. Legacy Identity Protection user/sign-in
    risk policies are emitted as INFO stubs (no Get-Mg* equivalent).

    WHY PS-ONLY:
    Conditional Access risk policies are now the recommended approach for Identity
    Protection. They are readable via Get-MgIdentityConditionalAccessPolicy. The
    legacy /identity/identityProtection/userRiskPolicies endpoint is a beta API with
    no corresponding Get-Mg* cmdlet in the current module — those checks emit INFO stubs.

    NOTE:
    Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy is used to check if Security
    Defaults are active (Security Defaults block CA risk policies).

    SEE ALSO (Graph variant):
        scripts/modules/IdentityProtection/Test-RiskPolicies.ps1

    Required connection:
        Connect-MgGraph -Scopes "Policy.Read.All","IdentityRiskyUser.Read.All"

    Required scopes:
        Policy.Read.All  (CA policies + Security Defaults)
        IdentityRiskyUser.Read.All  (risk context)

    Required modules:
        Microsoft.Graph.Identity.SignIns

    License: Entra ID P2 (E5) for risk-based CA
    SC-300 Domain: Identity Protection

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-RiskPolicies {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all CA policies once
    # -------------------------------------------------------------------------
    $caPolicies = $null
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'RPL-001' `
            -Category 'IdentityProtection' `
            -Name 'Risk-Based CA Policy Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @()))
        return $results
    }

    $enabledPolicies = @($caPolicies | Where-Object { $_.State -eq 'enabled' })

    # -------------------------------------------------------------------------
    # RPL-001: User risk policy (CA-based)
    # Look for CA policies with userRiskLevels condition set
    # -------------------------------------------------------------------------
    $userRiskPolicies = @($enabledPolicies | Where-Object {
        $_.Conditions.UserRiskLevels -and $_.Conditions.UserRiskLevels.Count -gt 0
    })

    if ($userRiskPolicies.Count -eq 0) {
        $rpl001Status = 'HIGH'
        $rpl001Detail = 'No enabled Conditional Access policy with user risk conditions found. High-risk users can continue to authenticate without forced password reset or block.'
    }
    else {
        # Check coverage: block or require password change for high-risk users
        $blockOrRemediate = @($userRiskPolicies | Where-Object {
            $_.GrantControls.BuiltInControls -contains 'block' -or
            $_.GrantControls.BuiltInControls -contains 'passwordChange'
        })

        $highRiskCovered = @($userRiskPolicies | Where-Object {
            $_.Conditions.UserRiskLevels -contains 'high'
        })

        $policyNames = ($userRiskPolicies | ForEach-Object { $_.DisplayName }) -join ', '

        if ($highRiskCovered.Count -eq 0) {
            $rpl001Status = 'MEDIUM'
            $rpl001Detail = "User risk policies exist ($policyNames) but none explicitly cover 'high' risk level users."
        }
        elseif ($blockOrRemediate.Count -eq 0) {
            $rpl001Status = 'MEDIUM'
            $rpl001Detail = "User risk policies exist ($policyNames) but controls do not include block or password change. Risk is flagged but not mitigated."
        }
        else {
            $rpl001Status = 'PASS'
            $rpl001Detail = "$($userRiskPolicies.Count) CA policy/policies with user risk conditions: $policyNames. High-risk level covered: $($highRiskCovered.Count). Remediation/block controls: $($blockOrRemediate.Count)."
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RPL-001' `
        -Category 'IdentityProtection' `
        -Name 'User Risk Policy (Conditional Access)' `
        -Status $rpl001Status `
        -Detail $rpl001Detail `
        -Recommendation 'Create a CA policy targeting All Users, condition User risk = High, grant = Require password change (for self-remediation) or block. Ensure users have SSPR enabled for password change to work.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
        -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # RPL-002: Sign-in risk policy (CA-based)
    # -------------------------------------------------------------------------
    $signInRiskPolicies = @($enabledPolicies | Where-Object {
        $_.Conditions.SignInRiskLevels -and $_.Conditions.SignInRiskLevels.Count -gt 0
    })

    if ($signInRiskPolicies.Count -eq 0) {
        $rpl002Status = 'HIGH'
        $rpl002Detail = 'No enabled Conditional Access policy with sign-in risk conditions found. High-risk sign-ins can proceed without MFA challenge or block.'
    }
    else {
        $mfaForHighRisk = @($signInRiskPolicies | Where-Object {
            $_.Conditions.SignInRiskLevels -contains 'high' -and
            ($_.GrantControls.BuiltInControls -contains 'mfa' -or
             $_.GrantControls.BuiltInControls -contains 'block')
        })

        $policyNames = ($signInRiskPolicies | ForEach-Object { $_.DisplayName }) -join ', '

        if ($mfaForHighRisk.Count -eq 0) {
            $rpl002Status = 'MEDIUM'
            $rpl002Detail = "Sign-in risk policies exist ($policyNames) but none require MFA or block for high-risk sign-ins."
        }
        else {
            $rpl002Status = 'PASS'
            $rpl002Detail = "$($signInRiskPolicies.Count) CA policy/policies with sign-in risk conditions: $policyNames. Policies enforcing MFA/block for high-risk: $($mfaForHighRisk.Count)."
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RPL-002' `
        -Category 'IdentityProtection' `
        -Name 'Sign-In Risk Policy (Conditional Access)' `
        -Status $rpl002Status `
        -Detail $rpl002Detail `
        -Recommendation 'Create a CA policy targeting All Users, condition Sign-in risk = High, grant = Require MFA. Consider also blocking medium-risk sign-ins or requiring MFA for them. Medium risk covers leaked credentials and password spray.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
        -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # RPL-003: Legacy Identity Protection user/sign-in risk policies — INFO STUB
    # /identity/identityProtection/userRiskPolicies has no Get-Mg* equivalent
    # -------------------------------------------------------------------------
    $rpl003Detail  = 'Legacy Identity Protection user risk and sign-in risk policies '
    $rpl003Detail += '(/identity/identityProtection/userRiskPolicies, /signInRiskPolicies) '
    $rpl003Detail += 'are beta API endpoints with no Get-Mg* equivalent in the current module. '
    $rpl003Detail += 'These legacy policies are deprecated in favor of Conditional Access risk policies (checked in RPL-001/RPL-002). '
    $rpl003Detail += 'Manual verification: Entra ID portal → Protection → Identity Protection → '
    $rpl003Detail += 'User risk policy + Sign-in risk policy. '
    $rpl003Detail += 'If legacy policies are enabled, migrate them to Conditional Access for greater flexibility and control. '
    $rpl003Detail += 'For automated check, use the Graph variant: scripts/modules/IdentityProtection/Test-RiskPolicies.ps1.'

    $results.Add((New-CheckResult `
        -CheckId 'RPL-003' `
        -Category 'IdentityProtection' `
        -Name 'Legacy Identity Protection Risk Policies' `
        -Status 'INFO' `
        -Detail $rpl003Detail `
        -Recommendation 'Verify legacy risk policies in the Entra ID Protection portal. Migrate any enabled legacy policies to Conditional Access. Legacy policies cannot be tuned with the same granularity as CA policies.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
        -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # RPL-004: Security Defaults compatibility check
    # Security Defaults disable Conditional Access — risk policies won't work
    # -------------------------------------------------------------------------
    try {
        $secDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop

        if ($secDefaults.IsEnabled -eq $true) {
            $rpl004Status = 'HIGH'
            $rpl004Detail = 'Security Defaults are ENABLED. Security Defaults and Conditional Access risk policies are mutually exclusive. Your risk-based CA policies (RPL-001, RPL-002) are NOT ACTIVE while Security Defaults are on. To use Identity Protection + CA risk policies, disable Security Defaults and switch to Conditional Access MFA policies.'
        }
        else {
            $rpl004Status = 'PASS'
            $rpl004Detail = 'Security Defaults are disabled. Conditional Access risk policies can be used without conflict. Ensure you have equivalent CA policies to replace Security Defaults MFA enforcement (see Authentication module).'
        }
    }
    catch {
        $rpl004Status = 'INFO'
        $rpl004Detail = "Security Defaults status could not be determined. Error: $_. Verify manually in Entra ID portal → Properties → Security defaults."
    }

    $results.Add((New-CheckResult `
        -CheckId 'RPL-004' `
        -Category 'IdentityProtection' `
        -Name 'Security Defaults vs. CA Risk Policies Compatibility' `
        -Status $rpl004Status `
        -Detail $rpl004Detail `
        -Recommendation 'If Security Defaults are enabled, disable them and replace with: (1) CA MFA policy for all users, (2) CA MFA for admins, (3) CA block legacy auth, (4) CA user risk policy, (5) CA sign-in risk policy. All five are needed before disabling Security Defaults.' `
        -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults' `
        -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    return $results
}
