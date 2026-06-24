#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Checks Entra ID Password Protection and Smart Lockout configuration.
.DESCRIPTION
    Evaluates whether Entra Password Protection (banned password list) is enabled,
    whether a custom banned password list is configured, on-premises password
    protection agent presence (hybrid), and smart lockout policy settings.
    Checks: PWD-001 through PWD-004.
.NOTES
    Required Permissions:
        Policy.Read.All
        Directory.Read.All
    License: Custom banned password list requires Entra ID P1 (E3);
             On-premises password protection requires Entra ID P1 or P2
#>

function Test-PasswordProtection {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Detect hybrid status once for PWD-003
    $isHybrid = $false
    try {
        $org = Get-MgOrganization -Property 'onPremisesSyncEnabled' -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled -eq $true
    }
    catch {
        Write-Verbose "Could not determine hybrid status: $_"
    }

    # Helper: fetch directory settings by display name
    function Get-DirectorySettingByName {
        param([string]$SettingName)
        $settings = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/settings' `
            -ErrorAction Stop
        $settings.value | Where-Object { $_.displayName -eq $SettingName } | Select-Object -First 1
    }

    # PWD-001 & PWD-002: Password Protection — banned passwords and custom list
    # Both checks share the same directory setting object (Password Rule Settings)
    try {
        $pwdSetting = Get-DirectorySettingByName -SettingName 'Password Rule Settings'

        if ($null -eq $pwdSetting) {
            # Setting not present means default (Microsoft global banned list is always active,
            # but Entra Password Protection enhanced enforcement is not configured)
            $results.Add((New-AssessmentResult `
                -CheckName 'PWD-001: Entra Password Protection (Banned Passwords)' `
                -Status    'Warning' `
                -Detail    "Password Rule Settings not found in tenant directory settings. Entra ID Password Protection (enhanced banned password enforcement) is not explicitly configured. Microsoft's global banned password list is still applied at authentication." `
                -Recommendation 'Configure Entra ID Password Protection in Entra admin center under Security > Authentication methods > Password protection. Enable it and set the mode to Enforced (not Audit).' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -Category  'Authentication' `
                -Severity  'Medium' `
                -CisControl ''))

            $results.Add((New-AssessmentResult `
                -CheckName 'PWD-002: Custom Banned Password List' `
                -Status    'Warning' `
                -Detail    "Password Rule Settings not configured. No custom banned password list has been defined." `
                -Recommendation 'Add a custom banned password list with company-specific terms (company name, product names, abbreviations, city names). This prevents password spraying against predictable passwords.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -Category  'Authentication' `
                -Severity  'Low' `
                -CisControl ''))
        }
        else {
            # Parse the setting values
            $values = @{}
            foreach ($v in $pwdSetting.values) { $values[$v.name] = $v.value }

            $enableBannedPasswordCheck = $values['EnableBannedPasswordCheck']
            $bannedPasswordCheckOnPrem = $values['BannedPasswordCheckOnPremisesMode']
            $customBannedPasswords = $values['BannedPasswordList']
            $enableBannedPasswordOnPrem = $values['EnableBannedPasswordCheckOnPremises']

            $bannedEnabled = $enableBannedPasswordCheck -eq 'True' -or $enableBannedPasswordCheck -eq $true

            # PWD-001
            $results.Add((New-AssessmentResult `
                -CheckName 'PWD-001: Entra Password Protection (Banned Passwords)' `
                -Status    (if ($bannedEnabled) { 'Pass' } else { 'Warning' }) `
                -Detail    "EnableBannedPasswordCheck: $enableBannedPasswordCheck. On-premises mode: $bannedPasswordCheckOnPrem. On-premises enabled: $enableBannedPasswordOnPrem." `
                -Recommendation 'Ensure EnableBannedPasswordCheck is true and the mode is set to Enforced (not Audit) for both cloud and on-premises.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -Category  'Authentication' `
                -Severity  (if (-not $bannedEnabled) { 'Medium' } else { 'Info' }) `
                -CisControl ''))

            # PWD-002
            $hasCustomList = -not [string]::IsNullOrWhiteSpace($customBannedPasswords)
            $customListWordCount = if ($hasCustomList) {
                ($customBannedPasswords -split "`n" | Where-Object { $_ -ne '' }).Count
            } else { 0 }

            $results.Add((New-AssessmentResult `
                -CheckName 'PWD-002: Custom Banned Password List' `
                -Status    (if ($hasCustomList) { 'Pass' } else { 'Warning' }) `
                -Detail    "Custom banned password list configured: $hasCustomList. Approximate word count: $customListWordCount entries." `
                -Recommendation 'Add a custom banned password list containing company-specific terms. Minimum recommended: company name, product names, city, and common substitutions (e.g., P@ssw0rd variants).' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -Category  'Authentication' `
                -Severity  (if (-not $hasCustomList) { 'Low' } else { 'Info' }) `
                -CisControl ''))
        }
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'PWD-001: Password Protection Settings' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Directory.Read.All. Error: $_" `
            -Recommendation 'Grant Directory.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # PWD-003: On-premises password protection agent (hybrid)
    if (-not $isHybrid) {
        $results.Add((New-AssessmentResult `
            -CheckName 'PWD-003: On-Premises Password Protection Agent' `
            -Status    'Info' `
            -Detail    "Tenant is cloud-only (onPremisesSyncEnabled: false). On-premises Password Protection agent check is not applicable." `
            -Recommendation 'No action required for cloud-only tenants.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
            -Category  'Authentication' `
            -Severity  'Info' `
            -CisControl ''))
    }
    else {
        # The Graph API does not expose on-premises Password Protection agent health directly.
        # It can be inferred from directory setting EnableBannedPasswordCheckOnPremises.
        try {
            $pwdSetting = Get-DirectorySettingByName -SettingName 'Password Rule Settings'
            if ($pwdSetting) {
                $values = @{}
                foreach ($v in $pwdSetting.values) { $values[$v.name] = $v.value }
                $onPremEnabled = $values['EnableBannedPasswordCheckOnPremises']
                $onPremMode = $values['BannedPasswordCheckOnPremisesMode']

                $results.Add((New-AssessmentResult `
                    -CheckName 'PWD-003: On-Premises Password Protection' `
                    -Status    (if ($onPremEnabled -eq 'True') { 'Pass' } else { 'Warning' }) `
                    -Detail    "EnableBannedPasswordCheckOnPremises: $onPremEnabled. Mode: $onPremMode. Hybrid tenant detected — on-premises Password Protection agent should be deployed to all DCs." `
                    -Recommendation 'Deploy the Entra Password Protection agent on all Domain Controllers. Set mode to Enforced once validated in Audit mode. This applies the same banned password policy to on-premises AD password changes.' `
                    -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
                    -Category  'Authentication' `
                    -Severity  (if ($onPremEnabled -ne 'True') { 'Medium' } else { 'Info' }) `
                    -CisControl ''))
            }
            else {
                $results.Add((New-AssessmentResult `
                    -CheckName 'PWD-003: On-Premises Password Protection' `
                    -Status    'Warning' `
                    -Detail    "Password Rule Settings not configured. Hybrid tenant — on-premises Password Protection agent status cannot be confirmed via Graph API. Manual verification required." `
                    -Recommendation 'Verify via: Get-AzureADPasswordProtectionDCAgent on a Domain Controller, or check the Entra admin center > Security > Authentication methods > Password protection.' `
                    -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
                    -Category  'Authentication' `
                    -Severity  'Medium' `
                    -CisControl ''))
            }
        }
        catch {
            $results.Add((New-AssessmentResult `
                -CheckName 'PWD-003: On-Premises Password Protection' `
                -Status    'Info' `
                -Detail    "Check skipped: insufficient permissions. Required: Directory.Read.All. Error: $_" `
                -Recommendation 'Grant Directory.Read.All to the service principal.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
                -Category  'Authentication' `
                -Severity  'Info'))
        }
    }

    # PWD-004: Smart Lockout configuration
    try {
        # Smart lockout settings live in the authenticationMethodsPolicy or in directory settings
        # The preferred API is GET /identity/authenticationMethods/authenticationMethodsPolicy (v1.0)
        # which includes lockoutThreshold and lockoutDurationInSeconds at the top level.
        $authPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/authenticationMethods/authenticationMethodsPolicy' `
            -ErrorAction Stop

        $threshold = $authPolicy.registrationEnforcement  # wrong field — smart lockout is separate
        # Smart lockout is actually in: GET /v1.0/settings → Password Rule Settings
        # OR via beta: GET /beta/policies/authenticationMethodsPolicy
        # Fallback to directory settings approach

        # Try the directory settings approach
        $pwdSetting = Get-DirectorySettingByName -SettingName 'Password Rule Settings'

        $lockoutThreshold = $null
        $lockoutDurationSeconds = $null

        if ($pwdSetting) {
            $values = @{}
            foreach ($v in $pwdSetting.values) { $values[$v.name] = $v.value }
            $lockoutThreshold = $values['LockoutThreshold']
            $lockoutDurationSeconds = $values['LockoutDurationInSeconds']
        }

        if ($null -eq $lockoutThreshold) {
            # Microsoft default: threshold=10, duration=60s
            $results.Add((New-AssessmentResult `
                -CheckName 'PWD-004: Smart Lockout Policy' `
                -Status    'Info' `
                -Detail    "Smart lockout settings not explicitly configured in directory settings. Microsoft default applies: threshold=10 attempts, duration=60 seconds." `
                -Recommendation 'Review smart lockout defaults. Consider lowering the threshold to 5-8 for admin accounts. Access via Entra admin center > Security > Authentication methods > Password protection.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout' `
                -Category  'Authentication' `
                -Severity  'Info' `
                -CisControl ''))
        }
        else {
            $thresholdInt = [int]$lockoutThreshold
            $durationInt = [int]$lockoutDurationSeconds

            $thresholdRisky = $thresholdInt -gt 10
            $durationRisky = $durationInt -lt 60

            $status = if ($thresholdRisky -or $durationRisky) { 'Warning' } else { 'Pass' }

            $results.Add((New-AssessmentResult `
                -CheckName 'PWD-004: Smart Lockout Policy' `
                -Status    $status `
                -Detail    "Lockout threshold: $thresholdInt attempts. Lockout duration: $durationInt seconds. Threshold >10 or duration <60s increases risk of successful password spray attacks." `
                -Recommendation 'Set lockout threshold to ≤10 (recommend 5-8). Set lockout duration to ≥60 seconds. For admin accounts, use Conditional Access to block after fewer failures.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout' `
                -Category  'Authentication' `
                -Severity  (if ($status -eq 'Warning') { 'Medium' } else { 'Info' }) `
                -MitreId   'T1110.003' `
                -MitreTactic 'CredentialAccess' `
                -CisControl ''))
        }
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'PWD-004: Smart Lockout Policy' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Policy.Read.All, Directory.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All and Directory.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    return $results
}
