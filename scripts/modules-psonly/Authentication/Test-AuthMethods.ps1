#Requires -Version 7.0

<#
.SYNOPSIS
    Checks Entra ID authentication methods policy configuration (PS-only variant).

.DESCRIPTION
    PS-ONLY VARIANT — No App Registration required.

    Evaluates SMS/voice/Authenticator (number matching)/FIDO2/TAP/CBA settings in the
    Authentication Methods Policy using the PowerShell SDK cmdlet
    Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration.

    The original script used Invoke-MgGraphRequest to call the raw REST endpoint:
        GET /v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/<name>
    This variant replaces every such call with the SDK equivalent:
        Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
            -AuthenticationMethodConfigurationId <name>

    The returned object exposes the same .State and .AdditionalProperties (featureSettings, etc.)
    as the raw REST response. Check IDs, thresholds, and all logic are identical.

    Checks: AMT-001 through AMT-006.

.NOTES
    ---- PS-ONLY VARIANT ----
    WHY PS-ONLY:
        The original script (modules/Authentication/Test-AuthMethods.ps1) used Invoke-MgGraphRequest
        with a service principal. This variant uses Connect-MgGraph with interactive delegated auth
        and the Graph PowerShell SDK cmdlet, so no App Registration or certificate is required.

    SEE ALSO (Graph/App-Registration variant):
        scripts/modules/Authentication/Test-AuthMethods.ps1

    Required Connection  : Connect-MgGraph -Scopes "Policy.Read.All"
                           (Run Connect-PSOnly.ps1 or connect manually before calling this function)

    Required Module      : Microsoft.Graph.Identity.SignIns

    Cmdlets Used         : Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration

    Valid -AuthenticationMethodConfigurationId values:
        'sms'
        'voice'
        'microsoftAuthenticatorAuthenticationMethod'
        'fido2'
        'temporaryAccessPass'
        'x509Certificate'
        'email'
        'softwareOath'

    Required Scope       : Policy.Read.All
    License Required     : E3 minimum; FIDO2/CBA may require additional configuration

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-AuthMethods {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Helper: wraps the SDK cmdlet, mirrors the original Get-AuthMethodConfig shape
    # Returns an object with .state and .featureSettings populated from
    # AdditionalProperties (the SDK stores non-base properties there).
    # -------------------------------------------------------------------------
    function Get-AuthMethodConfig {
        param([string]$MethodName)

        $raw = Get-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration `
                   -AuthenticationMethodConfigurationId $MethodName `
                   -ErrorAction Stop

        # The SDK cmdlet returns a typed object. .State is a direct property.
        # Extended properties (featureSettings, keyRestrictions, etc.) live in AdditionalProperties.
        $obj = [PSCustomObject]@{
            state              = $raw.State
            featureSettings    = $raw.AdditionalProperties['featureSettings']
            isSelfServiceRegistrationAllowed = $raw.AdditionalProperties['isSelfServiceRegistrationAllowed']
            keyRestrictions    = $raw.AdditionalProperties['keyRestrictions']
            isUsableOnce       = $raw.AdditionalProperties['isUsableOnce']
            defaultLifetimeInMinutes = $raw.AdditionalProperties['defaultLifetimeInMinutes']
            maximumLifetimeInMinutes = $raw.AdditionalProperties['maximumLifetimeInMinutes']
            authenticationModeConfiguration = $raw.AdditionalProperties['authenticationModeConfiguration']
        }
        return $obj
    }

    # -------------------------------------------------------------------------
    # AMT-001: SMS authentication
    # -------------------------------------------------------------------------
    try {
        $smsConfig  = Get-AuthMethodConfig -MethodName 'sms'
        $smsEnabled = $smsConfig.state -eq 'enabled'

        $results.Add((New-CheckResult `
            -CheckId        'AMT-001' `
            -Category       'Authentication' `
            -Name           'SMS Authentication Enabled' `
            -Status         (if ($smsEnabled) { 'MEDIUM' } else { 'PASS' }) `
            -Detail         "SMS authentication state: $($smsConfig.state). SMS-based MFA is vulnerable to SIM swapping and SS7 interception attacks." `
            -Recommendation 'Disable SMS authentication if possible. Migrate users to Microsoft Authenticator (push with number matching) or FIDO2 keys. If SMS must remain for legacy users, restrict with a target group and set a migration timeline.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -CISControl     'CIS M365 1.1.6' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'AMT-001' `
            -Category       'Authentication' `
            -Name           'SMS Authentication' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All via Connect-MgGraph. Error: $_" `
            -Recommendation 'Run: Connect-MgGraph -Scopes "Policy.Read.All" and retry.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AMT-002: Voice call authentication
    # -------------------------------------------------------------------------
    try {
        $voiceConfig  = Get-AuthMethodConfig -MethodName 'voice'
        $voiceEnabled = $voiceConfig.state -eq 'enabled'

        $results.Add((New-CheckResult `
            -CheckId        'AMT-002' `
            -Category       'Authentication' `
            -Name           'Voice Call Authentication Enabled' `
            -Status         (if ($voiceEnabled) { 'MEDIUM' } else { 'PASS' }) `
            -Detail         "Voice call authentication state: $($voiceConfig.state). Voice calls share SIM-swap and call-forwarding risks with SMS." `
            -Recommendation 'Disable voice call authentication. Migrate users to Microsoft Authenticator with number matching or FIDO2.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -CISControl     'CIS M365 1.1.6' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'AMT-002' `
            -Category       'Authentication' `
            -Name           'Voice Call Authentication' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All via Connect-MgGraph. Error: $_" `
            -Recommendation 'Run: Connect-MgGraph -Scopes "Policy.Read.All" and retry.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AMT-003: Microsoft Authenticator — number matching
    # -------------------------------------------------------------------------
    try {
        $authConfig  = Get-AuthMethodConfig -MethodName 'microsoftAuthenticatorAuthenticationMethod'
        $authEnabled = $authConfig.state -eq 'enabled'

        $featureSettings       = $authConfig.featureSettings
        $numberMatchingEnabled = $false
        $companionAppState     = $null

        if ($featureSettings) {
            $numberMatchingEnabled = $featureSettings.numberMatchingRequiredState.state -eq 'enabled'
            $companionAppState     = $featureSettings.displayAppInformationRequiredState.state
        }

        $detail = if (-not $authEnabled) {
            'Microsoft Authenticator is DISABLED. This is the primary recommended MFA method.'
        }
        elseif (-not $numberMatchingEnabled) {
            "Microsoft Authenticator is enabled but NUMBER MATCHING is not enabled (state: $($featureSettings.numberMatchingRequiredState.state)). Without number matching, users are vulnerable to MFA fatigue (push spam) attacks."
        }
        else {
            "Microsoft Authenticator is enabled with number matching active. Additional context (display app info) state: $companionAppState."
        }

        $results.Add((New-CheckResult `
            -CheckId        'AMT-003' `
            -Category       'Authentication' `
            -Name           'Authenticator Number Matching' `
            -Status         (if (-not $authEnabled -or -not $numberMatchingEnabled) { 'HIGH' } else { 'PASS' }) `
            -Detail         $detail `
            -Recommendation 'Enable Microsoft Authenticator and set numberMatchingRequiredState to enabled. Also enable displayAppInformationRequiredState for additional context. This prevents MFA fatigue attacks.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match' `
            -CISControl     'CIS M365 1.1.5' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'AMT-003' `
            -Category       'Authentication' `
            -Name           'Authenticator Number Matching' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All via Connect-MgGraph. Error: $_" `
            -Recommendation 'Run: Connect-MgGraph -Scopes "Policy.Read.All" and retry.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AMT-004: FIDO2 security keys
    # -------------------------------------------------------------------------
    try {
        $fido2Config        = Get-AuthMethodConfig -MethodName 'fido2'
        $selfServiceAllowed = $fido2Config.isSelfServiceRegistrationAllowed
        $keyRestrictions    = $fido2Config.keyRestrictions

        $results.Add((New-CheckResult `
            -CheckId        'AMT-004' `
            -Category       'Authentication' `
            -Name           'FIDO2 Security Keys' `
            -Status         'INFO' `
            -Detail         "FIDO2 state: $($fido2Config.state). Self-service registration: $selfServiceAllowed. Key restrictions enforced: $($keyRestrictions.isEnforced). FIDO2 provides phishing-resistant MFA." `
            -Recommendation 'Enable FIDO2 security keys for privileged users and users who cannot use mobile apps. Consider restricting to approved hardware vendors via key restriction enforcement.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'AMT-004' `
            -Category       'Authentication' `
            -Name           'FIDO2 Security Keys' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All via Connect-MgGraph. Error: $_" `
            -Recommendation 'Run: Connect-MgGraph -Scopes "Policy.Read.All" and retry.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AMT-005: Temporary Access Pass (TAP)
    # -------------------------------------------------------------------------
    try {
        $tapConfig                = Get-AuthMethodConfig -MethodName 'temporaryAccessPass'
        $tapEnabled               = $tapConfig.state -eq 'enabled'
        $isUsableOnce             = $tapConfig.isUsableOnce
        $defaultLifetimeInMinutes = $tapConfig.defaultLifetimeInMinutes
        $maximumLifetimeInMinutes = $tapConfig.maximumLifetimeInMinutes

        $detail   = "TAP state: $($tapConfig.state). One-time use: $isUsableOnce. Default lifetime: $defaultLifetimeInMinutes min. Maximum lifetime: $maximumLifetimeInMinutes min."
        $tapRisky = $tapEnabled -and (-not $isUsableOnce) -and ($maximumLifetimeInMinutes -gt 480)

        $results.Add((New-CheckResult `
            -CheckId        'AMT-005' `
            -Category       'Authentication' `
            -Name           'Temporary Access Pass (TAP)' `
            -Status         (if ($tapRisky) { 'MEDIUM' } else { 'INFO' }) `
            -Detail         $detail `
            -Recommendation 'If TAP is enabled, enforce isUsableOnce=true and limit maximumLifetimeInMinutes to <=480 (8 hours). TAP is useful for onboarding/recovery but must be short-lived and one-time-use.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'AMT-005' `
            -Category       'Authentication' `
            -Name           'Temporary Access Pass' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All via Connect-MgGraph. Error: $_" `
            -Recommendation 'Run: Connect-MgGraph -Scopes "Policy.Read.All" and retry.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # AMT-006: Certificate-based authentication (CBA)
    # -------------------------------------------------------------------------
    try {
        $cbaConfig = Get-AuthMethodConfig -MethodName 'x509Certificate'
        $authMode  = $cbaConfig.authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode

        $results.Add((New-CheckResult `
            -CheckId        'AMT-006' `
            -Category       'Authentication' `
            -Name           'Certificate-Based Authentication (CBA)' `
            -Status         'INFO' `
            -Detail         "CBA state: $($cbaConfig.state). Default authentication mode: $authMode. CBA provides phishing-resistant MFA using smart cards or device certificates." `
            -Recommendation 'CBA is recommended for highly privileged accounts and regulated environments. If enabled, configure certificate authority bindings and ensure revocation checking is active.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-certificate-based-authentication' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'AMT-006' `
            -Category       'Authentication' `
            -Name           'Certificate-Based Authentication' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or CBA not configured. Required: Policy.Read.All via Connect-MgGraph. Error: $_" `
            -Recommendation 'Run: Connect-MgGraph -Scopes "Policy.Read.All" and retry.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-certificate-based-authentication' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
