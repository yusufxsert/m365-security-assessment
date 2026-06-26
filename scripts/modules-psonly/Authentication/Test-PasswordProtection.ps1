#Requires -Version 7.0

<#
.SYNOPSIS
    Checks Entra ID Password Protection and Smart Lockout configuration. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — converts New-AssessmentResult → New-CheckResult, and uses
    Invoke-MgGraphRequest for the directory settings endpoint (no Get-Mg* cmdlet
    for /settings exists) plus Get-MgOrganization for hybrid detection.

    WHY PS-ONLY:
    The original uses New-AssessmentResult (different helper with different parameters).
    This variant uses New-CheckResult with the standard CheckId-based parameter set.
    The directory settings endpoint (/settings) has no Get-Mg* equivalent — we keep
    Invoke-MgGraphRequest for that specific call only (confirmed Graph path).
    Get-MgOrganization is the PS-only equivalent of /organization for hybrid detection.

    NOTE on Smart Lockout:
    Smart lockout settings are stored in the 'Password Rule Settings' directory setting.
    There is no dedicated Get-MgPolicy* cmdlet for smart lockout. Invoke-MgGraphRequest
    is used to retrieve the directory settings object (confirmed v1.0 path).

    SEE ALSO (Graph variant):
        scripts/modules/Authentication/Test-PasswordProtection.ps1

    Required connection:
        Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"

    Required scopes:
        Policy.Read.All
        Directory.Read.All

    Required modules:
        Microsoft.Graph.Identity.DirectoryManagement  (Get-MgOrganization)
        Microsoft.Graph.Authentication                (Invoke-MgGraphRequest)

    License: Custom banned password list requires Entra ID P1 (E3);
             On-premises password protection requires Entra ID P1 or P2
    SC-300 Domain: Authentication & Access Management

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.

    Status mapping from original (New-AssessmentResult) to New-CheckResult:
        Pass    → PASS
        Warning → MEDIUM (or HIGH where severity was Medium/High)
        Fail    → HIGH
        Info    → INFO
#>

function Test-PasswordProtection {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Detect hybrid status once — used for PWD-003
    # Get-MgOrganization is the PS-only equivalent of GET /organization
    # -------------------------------------------------------------------------
    $isHybrid = $false
    try {
        $org      = Get-MgOrganization -Property 'onPremisesSyncEnabled' -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled -eq $true
    }
    catch {
        Write-Verbose "Could not determine hybrid status: $_"
    }

    # Helper: fetch directory settings by display name
    # No Get-Mg* for /settings — Invoke-MgGraphRequest is the confirmed path
    function Get-DirectorySettingByName {
        param([string]$SettingName)
        $settings = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/settings' `
            -ErrorAction Stop
        $settings.value | Where-Object { $_.displayName -eq $SettingName } | Select-Object -First 1
    }

    # -------------------------------------------------------------------------
    # PWD-001 & PWD-002: Password Protection — banned passwords and custom list
    # Both checks share the same directory setting object (Password Rule Settings)
    # -------------------------------------------------------------------------
    try {
        $pwdSetting = Get-DirectorySettingByName -SettingName 'Password Rule Settings'

        if ($null -eq $pwdSetting) {
            # Setting not present = Entra Password Protection enhanced enforcement not configured.
            # Microsoft's global banned password list is still active at authentication.
            $results.Add((New-CheckResult `
                -CheckId        'PWD-001' `
                -Category       'Authentication' `
                -Name           'Entra Password Protection (Banned Passwords)' `
                -Status         'MEDIUM' `
                -Detail         "Password Rule Settings not found in tenant directory settings. Entra ID Password Protection (enhanced banned password enforcement) is not explicitly configured. Microsoft's global banned password list is still applied at authentication." `
                -Recommendation 'Configure Entra ID Password Protection in Entra admin center: Security > Authentication methods > Password protection. Enable it and set the mode to Enforced (not Audit).' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))

            $results.Add((New-CheckResult `
                -CheckId        'PWD-002' `
                -Category       'Authentication' `
                -Name           'Custom Banned Password List' `
                -Status         'LOW' `
                -Detail         'Password Rule Settings not configured. No custom banned password list has been defined.' `
                -Recommendation 'Add a custom banned password list with company-specific terms (company name, product names, abbreviations, city names). This prevents password spraying against predictable passwords.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        else {
            # Parse the setting values
            $values = @{}
            foreach ($v in $pwdSetting.values) { $values[$v.name] = $v.value }

            $enableBannedPasswordCheck  = $values['EnableBannedPasswordCheck']
            $bannedPasswordCheckOnPrem  = $values['BannedPasswordCheckOnPremisesMode']
            $customBannedPasswords      = $values['BannedPasswordList']
            $enableBannedPasswordOnPrem = $values['EnableBannedPasswordCheckOnPremises']

            $bannedEnabled = $enableBannedPasswordCheck -eq 'True' -or $enableBannedPasswordCheck -eq $true

            # PWD-001
            $results.Add((New-CheckResult `
                -CheckId        'PWD-001' `
                -Category       'Authentication' `
                -Name           'Entra Password Protection (Banned Passwords)' `
                -Status         (if ($bannedEnabled) { 'PASS' } else { 'MEDIUM' }) `
                -Detail         "EnableBannedPasswordCheck: $enableBannedPasswordCheck. On-premises mode: $bannedPasswordCheckOnPrem. On-premises enabled: $enableBannedPasswordOnPrem." `
                -Recommendation 'Ensure EnableBannedPasswordCheck is true and the mode is set to Enforced (not Audit) for both cloud and on-premises.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))

            # PWD-002
            $hasCustomList = -not [string]::IsNullOrWhiteSpace($customBannedPasswords)
            $customListWordCount = if ($hasCustomList) {
                ($customBannedPasswords -split "`n" | Where-Object { $_ -ne '' }).Count
            } else { 0 }

            $results.Add((New-CheckResult `
                -CheckId        'PWD-002' `
                -Category       'Authentication' `
                -Name           'Custom Banned Password List' `
                -Status         (if ($hasCustomList) { 'PASS' } else { 'LOW' }) `
                -Detail         "Custom banned password list configured: $hasCustomList. Approximate word count: $customListWordCount entries." `
                -Recommendation 'Add a custom banned password list containing company-specific terms. Minimum recommended: company name, product names, city, and common substitutions (e.g., P@ssw0rd variants).' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'PWD-001' `
            -Category       'Authentication' `
            -Name           'Password Protection Settings' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or API error. Required: Directory.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Directory.Read.All".' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-password-ban-bad' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PWD-003: On-premises password protection agent (hybrid only)
    # -------------------------------------------------------------------------
    if (-not $isHybrid) {
        $results.Add((New-CheckResult `
            -CheckId        'PWD-003' `
            -Category       'Authentication' `
            -Name           'On-Premises Password Protection Agent' `
            -Status         'INFO' `
            -Detail         'Tenant is cloud-only (onPremisesSyncEnabled: false). On-premises Password Protection agent check is not applicable.' `
            -Recommendation 'No action required for cloud-only tenants.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    else {
        try {
            $pwdSetting = Get-DirectorySettingByName -SettingName 'Password Rule Settings'
            if ($pwdSetting) {
                $values = @{}
                foreach ($v in $pwdSetting.values) { $values[$v.name] = $v.value }
                $onPremEnabled = $values['EnableBannedPasswordCheckOnPremises']
                $onPremMode    = $values['BannedPasswordCheckOnPremisesMode']

                $pwd003Status = if ($onPremEnabled -eq 'True') { 'PASS' } else { 'MEDIUM' }

                $results.Add((New-CheckResult `
                    -CheckId        'PWD-003' `
                    -Category       'Authentication' `
                    -Name           'On-Premises Password Protection' `
                    -Status         $pwd003Status `
                    -Detail         "EnableBannedPasswordCheckOnPremises: $onPremEnabled. Mode: $onPremMode. Hybrid tenant detected — on-premises Password Protection agent should be deployed to all DCs." `
                    -Recommendation 'Deploy the Entra Password Protection agent on all Domain Controllers. Set mode to Enforced once validated in Audit mode. This applies the same banned password policy to on-premises AD password changes.' `
                    -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
                    -CISControl     '' `
                    -SC300Domain    'Authentication & Access Management' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
            else {
                $results.Add((New-CheckResult `
                    -CheckId        'PWD-003' `
                    -Category       'Authentication' `
                    -Name           'On-Premises Password Protection' `
                    -Status         'MEDIUM' `
                    -Detail         'Password Rule Settings not configured. Hybrid tenant — on-premises Password Protection agent status cannot be confirmed via Graph API. Manual verification required.' `
                    -Recommendation 'Verify via the Entra admin center: Security > Authentication methods > Password protection. Or check directly on a Domain Controller.' `
                    -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
                    -CISControl     '' `
                    -SC300Domain    'Authentication & Access Management' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId        'PWD-003' `
                -Category       'Authentication' `
                -Name           'On-Premises Password Protection' `
                -Status         'INFO' `
                -Detail         "Check skipped: insufficient permissions. Required: Directory.Read.All. Error: $_" `
                -Recommendation 'Connect-MgGraph -Scopes "Directory.Read.All".' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-password-ban-bad-on-premises-deploy' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }

    # -------------------------------------------------------------------------
    # PWD-004: Smart Lockout configuration
    # Smart lockout settings are in the 'Password Rule Settings' directory setting.
    # No Get-Mg* for this — Invoke-MgGraphRequest is used (confirmed v1.0 path).
    # -------------------------------------------------------------------------
    try {
        $pwdSetting = Get-DirectorySettingByName -SettingName 'Password Rule Settings'

        $lockoutThreshold       = $null
        $lockoutDurationSeconds = $null

        if ($pwdSetting) {
            $values = @{}
            foreach ($v in $pwdSetting.values) { $values[$v.name] = $v.value }
            $lockoutThreshold       = $values['LockoutThreshold']
            $lockoutDurationSeconds = $values['LockoutDurationInSeconds']
        }

        if ($null -eq $lockoutThreshold) {
            # Microsoft default: threshold=10, duration=60s
            $results.Add((New-CheckResult `
                -CheckId        'PWD-004' `
                -Category       'Authentication' `
                -Name           'Smart Lockout Policy' `
                -Status         'INFO' `
                -Detail         'Smart lockout settings not explicitly configured in directory settings. Microsoft default applies: threshold=10 attempts, duration=60 seconds.' `
                -Recommendation 'Review smart lockout defaults. Consider lowering the threshold to 5-8. Access via Entra admin center: Security > Authentication methods > Password protection.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        else {
            $thresholdInt = [int]$lockoutThreshold
            $durationInt  = [int]$lockoutDurationSeconds

            $thresholdRisky = $thresholdInt -gt 10
            $durationRisky  = $durationInt -lt 60

            $pwd004Status = if ($thresholdRisky -or $durationRisky) { 'MEDIUM' } else { 'PASS' }

            $results.Add((New-CheckResult `
                -CheckId        'PWD-004' `
                -Category       'Authentication' `
                -Name           'Smart Lockout Policy' `
                -Status         $pwd004Status `
                -Detail         "Lockout threshold: $thresholdInt attempts. Lockout duration: $durationInt seconds. Threshold >10 or duration <60s increases risk of successful password spray attacks." `
                -Recommendation 'Set lockout threshold to ≤10 (recommend 5-8). Set lockout duration to ≥60 seconds. For admin accounts, use Conditional Access to block after fewer failures.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'PWD-004' `
            -Category       'Authentication' `
            -Name           'Smart Lockout Policy' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or API error. Required: Policy.Read.All, Directory.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All".' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
