#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Checks Entra ID authentication methods policy configuration.
.DESCRIPTION
    Evaluates SMS/voice/Authenticator app (number matching)/FIDO2/TAP/CBA
    settings in the Authentication Methods Policy.
    Checks: AMT-001 through AMT-006.
.NOTES
    Required Permissions:
        Policy.Read.All
    License: E3 minimum; FIDO2/CBA may require additional configuration
#>

function Test-AuthMethods {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Helper: retrieve a single auth method configuration by method type name
    function Get-AuthMethodConfig {
        param([string]$MethodName)
        Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$MethodName" `
            -ErrorAction Stop
    }

    # AMT-001: SMS authentication
    try {
        $smsConfig = Get-AuthMethodConfig -MethodName 'sms'
        $smsEnabled = $smsConfig.state -eq 'enabled'

        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-001: SMS Authentication Enabled' `
            -Status    (if ($smsEnabled) { 'Warning' } else { 'Pass' }) `
            -Detail    "SMS authentication state: $($smsConfig.state). SMS-based MFA is vulnerable to SIM swapping and SS7 interception attacks." `
            -Recommendation 'Disable SMS authentication if possible. Migrate users to Microsoft Authenticator (push with number matching) or FIDO2 keys. If SMS must remain for legacy users, restrict with a target group and set a migration timeline.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -Category  'Authentication' `
            -Severity  (if ($smsEnabled) { 'Medium' } else { 'Info' }) `
            -MitreId   'T1111' `
            -MitreTactic 'CredentialAccess' `
            -CisControl 'CIS M365 1.1.6'))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-001: SMS Authentication' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # AMT-002: Voice call authentication
    try {
        $voiceConfig = Get-AuthMethodConfig -MethodName 'voice'
        $voiceEnabled = $voiceConfig.state -eq 'enabled'

        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-002: Voice Call Authentication Enabled' `
            -Status    (if ($voiceEnabled) { 'Warning' } else { 'Pass' }) `
            -Detail    "Voice call authentication state: $($voiceConfig.state). Voice calls share SIM-swap and call-forwarding risks with SMS." `
            -Recommendation 'Disable voice call authentication. Migrate users to Microsoft Authenticator with number matching or FIDO2.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -Category  'Authentication' `
            -Severity  (if ($voiceEnabled) { 'Medium' } else { 'Info' }) `
            -MitreId   'T1111' `
            -MitreTactic 'CredentialAccess' `
            -CisControl 'CIS M365 1.1.6'))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-002: Voice Call Authentication' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-phone-options' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # AMT-003: Microsoft Authenticator — number matching
    try {
        $authConfig = Get-AuthMethodConfig -MethodName 'microsoftAuthenticatorAuthenticationMethod'
        $authEnabled = $authConfig.state -eq 'enabled'

        # Number matching is in featureSettings
        $featureSettings = $authConfig.featureSettings
        $numberMatchingEnabled = $false
        $companionAppAllowedState = $null

        if ($featureSettings) {
            # numberMatchingRequiredState or displayAppInformationRequiredState
            $nmState = $featureSettings.numberMatchingRequiredState
            $numberMatchingEnabled = $nmState.state -eq 'enabled'
            $companionAppAllowedState = $featureSettings.displayAppInformationRequiredState.state
        }

        $status = if (-not $authEnabled) { 'Fail' }
                  elseif (-not $numberMatchingEnabled) { 'Fail' }
                  else { 'Pass' }

        $detail = if (-not $authEnabled) {
            "Microsoft Authenticator is DISABLED. This is the primary recommended MFA method."
        } elseif (-not $numberMatchingEnabled) {
            "Microsoft Authenticator is enabled but NUMBER MATCHING is not enabled (state: $($featureSettings.numberMatchingRequiredState.state)). Without number matching, users are vulnerable to MFA fatigue (push spam) attacks."
        } else {
            "Microsoft Authenticator is enabled with number matching active. Additional context (display app info) state: $companionAppAllowedState."
        }

        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-003: Authenticator Number Matching' `
            -Status    $status `
            -Detail    $detail `
            -Recommendation 'Enable Microsoft Authenticator and set numberMatchingRequiredState to enabled. Also enable displayAppInformationRequiredState for additional context (location/app info on push). This prevents MFA fatigue attacks.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match' `
            -Category  'Authentication' `
            -Severity  (if ($status -eq 'Fail') { 'High' } else { 'Info' }) `
            -MitreId   'T1621' `
            -MitreTactic 'CredentialAccess' `
            -CisControl 'CIS M365 1.1.5'))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-003: Authenticator Number Matching' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # AMT-004: FIDO2 security keys
    try {
        $fido2Config = Get-AuthMethodConfig -MethodName 'fido2'
        $fido2Enabled = $fido2Config.state -eq 'enabled'
        $selfServiceAllowed = $fido2Config.isSelfServiceRegistrationAllowed
        $keyRestrictions = $fido2Config.keyRestrictions

        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-004: FIDO2 Security Keys' `
            -Status    'Info' `
            -Detail    "FIDO2 state: $($fido2Config.state). Self-service registration: $selfServiceAllowed. Key restrictions enforced: $($keyRestrictions.isEnforced). FIDO2 provides phishing-resistant MFA." `
            -Recommendation 'Enable FIDO2 security keys for privileged users and users who cannot use mobile apps. Consider restricting to approved hardware vendors via key restriction enforcement.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys' `
            -Category  'Authentication' `
            -Severity  'Info' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-004: FIDO2 Security Keys' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # AMT-005: Temporary Access Pass (TAP)
    try {
        $tapConfig = Get-AuthMethodConfig -MethodName 'temporaryAccessPass'
        $tapEnabled = $tapConfig.state -eq 'enabled'
        $isUsableOnce = $tapConfig.isUsableOnce
        $defaultLifetimeInMinutes = $tapConfig.defaultLifetimeInMinutes
        $maximumLifetimeInMinutes = $tapConfig.maximumLifetimeInMinutes

        $detail = "TAP state: $($tapConfig.state). One-time use: $isUsableOnce. Default lifetime: $defaultLifetimeInMinutes min. Maximum lifetime: $maximumLifetimeInMinutes min."

        $status = if ($tapEnabled -and -not $isUsableOnce -and $maximumLifetimeInMinutes -gt 480) {
            'Warning'  # TAP on but reusable and long-lived
        } else { 'Info' }

        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-005: Temporary Access Pass (TAP)' `
            -Status    $status `
            -Detail    $detail `
            -Recommendation 'If TAP is enabled, enforce isUsableOnce=true and limit maximumLifetimeInMinutes to ≤480 (8 hours). TAP is useful for onboarding/recovery but must be short-lived and one-time-use.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass' `
            -Category  'Authentication' `
            -Severity  $status `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-005: Temporary Access Pass' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or method not configured. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-authentication-temporary-access-pass' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # AMT-006: Certificate-based authentication (CBA)
    try {
        $cbaConfig = Get-AuthMethodConfig -MethodName 'x509Certificate'
        $cbaEnabled = $cbaConfig.state -eq 'enabled'
        $authMode = $cbaConfig.authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode

        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-006: Certificate-Based Authentication (CBA)' `
            -Status    'Info' `
            -Detail    "CBA state: $($cbaConfig.state). Default authentication mode: $authMode. CBA provides phishing-resistant MFA using smart cards or device certificates." `
            -Recommendation 'CBA is recommended for highly privileged accounts and government/regulated environments. If enabled, configure certificate authority bindings and ensure revocation checking is active.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-certificate-based-authentication' `
            -Category  'Authentication' `
            -Severity  'Info' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'AMT-006: Certificate-Based Authentication' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or CBA not configured. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-certificate-based-authentication' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    return $results
}
