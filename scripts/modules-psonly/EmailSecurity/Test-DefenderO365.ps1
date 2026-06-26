#Requires -Version 7.0

<#
.SYNOPSIS
    Audits Microsoft Defender for Office 365 policy configuration (PS-only variant).

.DESCRIPTION
    PS-ONLY VARIANT — No App Registration required.

    Test-DefenderO365 evaluates anti-phishing, Safe Attachments, Safe Links, anti-malware,
    outbound anti-spam, and preset security policy adoption using Exchange Online PowerShell
    cmdlets exclusively.

    This variant requires an active Exchange Online session (Connect-ExchangeOnline). If EXO
    is not connected, each check emits one INFO result explaining how to connect, then returns.
    There is NO Graph Secure Score fallback in this variant — connect EXO first.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

.NOTES
    ---- PS-ONLY VARIANT ----
    WHY PS-ONLY:
        The original script (modules/EmailSecurity/Test-DefenderO365.ps1) uses an App Registration
        (service principal + certificate) with Invoke-MgGraphRequest for a Secure Score fallback.
        This PS-only version uses Connect-ExchangeOnline (interactive, delegated) only, removing
        the Graph fallback entirely. Suitable for ad-hoc assessment without an App Registration.

    SEE ALSO (Graph/App-Registration variant):
        scripts/modules/EmailSecurity/Test-DefenderO365.ps1

    Required Connection  : Connect-ExchangeOnline
                           (Run Connect-PSOnly.ps1 or: Connect-ExchangeOnline -UserPrincipalName <UPN>)
    Required Module      : ExchangeOnlineManagement
    Cmdlets Used         : Get-AntiPhishPolicy, Get-AntiPhishRule
                           Get-SafeAttachmentPolicy, Get-SafeAttachmentRule
                           Get-SafeLinksPolicy, Get-SafeLinksRule
                           Get-MalwareFilterPolicy
                           Get-HostedOutboundSpamFilterPolicy
                           Get-EOPProtectionPolicyRule

    License Required     : E3 for anti-phishing, anti-malware, anti-spam
                           E5 / Defender for Office 365 P1 for Safe Attachments and Safe Links

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        DEF-001  Anti-phishing policy configured and key features enabled
        DEF-002  Anti-phishing impersonation protection targets
        DEF-003  Safe Attachments policy (requires E5 / Defender P1)
        DEF-004  Safe Links policy (requires E5 / Defender P1)
        DEF-005  Anti-malware policy
        DEF-006  Outbound anti-spam policy
        DEF-007  Preset security policies (Standard/Strict) adoption
#>

function Test-DefenderO365 {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Helper: check if EXO cmdlet is available
    # -------------------------------------------------------------------------
    function Test-EXOAvailable {
        param([string]$CmdletName)
        return [bool](Get-Command -Name $CmdletName -ErrorAction SilentlyContinue)
    }

    $exoConnected = Test-EXOAvailable -CmdletName 'Get-AntiPhishPolicy'

    if (-not $exoConnected) {
        # PS-only variant has no fallback — emit INFO per check and return
        $connectNote = 'ExchangeOnlineManagement module cmdlets are not available in this session. ' +
                       'This PS-only variant requires an active Exchange Online connection. ' +
                       'Run: Connect-ExchangeOnline -UserPrincipalName <UPN>'

        foreach ($checkId in @('DEF-001','DEF-002','DEF-003','DEF-004','DEF-005','DEF-006','DEF-007')) {
            $results.Add((New-CheckResult `
                -CheckId $checkId `
                -Category 'EmailSecurity' `
                -Name "Defender O365: $checkId — EXO Not Connected" `
                -Status 'INFO' `
                -Detail $connectNote `
                -Recommendation 'Connect Exchange Online using Connect-ExchangeOnline -UserPrincipalName <UPN> and re-run the assessment.' `
                -Reference 'https://learn.microsoft.com/powershell/exchange/connect-to-exchange-online-powershell' `
                -CISControl '' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        return $results
    }

    # -------------------------------------------------------------------------
    # DEF-001: Anti-phishing policy
    # -------------------------------------------------------------------------
    try {
        $antiPhishPolicies = @(Get-AntiPhishPolicy -ErrorAction Stop)
        $antiPhishRules    = @(Get-AntiPhishRule -ErrorAction Stop)

        $defaultPolicy  = $antiPhishPolicies | Where-Object { $_.IsDefault -eq $true }
        $customPolicies = $antiPhishPolicies | Where-Object { $_.IsDefault -ne $true }

        $mailboxIntelMissing = @($antiPhishPolicies | Where-Object { $_.EnableMailboxIntelligence -ne $true })
        $spoofIntelMissing   = @($antiPhishPolicies | Where-Object { $_.EnableSpoofIntelligence -ne $true })

        $def001Status = if ($customPolicies.Count -gt 0) { 'PASS' } else { 'HIGH' }
        $def001Detail = "Anti-phish policies: $($antiPhishPolicies.Count) total ($($customPolicies.Count) custom). " +
                        "EnableMailboxIntelligence missing on: $($mailboxIntelMissing.Count) policy/ies. " +
                        "EnableSpoofIntelligence missing on: $($spoofIntelMissing.Count) policy/ies."
        if ($customPolicies.Count -eq 0) {
            $def001Detail += ' Only the default policy exists — it applies to all users with baseline settings. Custom policies allow targeted configuration for high-value users.'
        }

        $affected = @()
        if ($mailboxIntelMissing.Count -gt 0 -or $spoofIntelMissing.Count -gt 0) {
            $def001Status = 'HIGH'
            $affected = @($mailboxIntelMissing + $spoofIntelMissing | ForEach-Object { $_.Name }) | Sort-Object -Unique
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEF-001' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Anti-Phishing Policy' `
            -Status $def001Status `
            -Detail $def001Detail `
            -Recommendation 'Create a custom anti-phishing policy targeting all users with EnableMailboxIntelligence, EnableSpoofIntelligence, and EnableOrganizationDomainsProtection all set to True. For executives, create a separate high-priority policy.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies-about' `
            -CISControl 'CIS M365 6.3' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects $affected))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEF-001' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Anti-Phishing Policy' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies-about' `
            -CISControl 'CIS M365 6.3' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEF-002: Impersonation protection targets
    # -------------------------------------------------------------------------
    try {
        $antiPhishPolicies2 = @(Get-AntiPhishPolicy -ErrorAction Stop)
        $withImpersonation  = @($antiPhishPolicies2 | Where-Object {
            $_.TargetedUsersToProtect.Count -gt 0 -or
            $_.EnableTargetedUserProtection -eq $true
        })

        $def002Status = if ($withImpersonation.Count -gt 0) { 'PASS' } else { 'MEDIUM' }
        $def002Detail = "Anti-phish policies with impersonation targets configured: $($withImpersonation.Count) of $($antiPhishPolicies2.Count). " +
                        "Impersonation protection identifies emails that mimic specific users (e.g. CEO, CFO)."

        $results.Add((New-CheckResult `
            -CheckId 'DEF-002' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Anti-Phishing Impersonation Protection' `
            -Status $def002Status `
            -Detail $def002Detail `
            -Recommendation 'Configure TargetedUsersToProtect in at least one anti-phishing policy to include executives, finance users, and IT admins. Enable EnableTargetedUserProtection = True.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies-about' `
            -CISControl 'CIS M365 6.3' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects $(if ($withImpersonation.Count -eq 0) { @('No policy with impersonation targets') } else { @() })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEF-002' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Anti-Phishing Impersonation Protection' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies-about' `
            -CISControl 'CIS M365 6.3' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEF-003: Safe Attachments
    # -------------------------------------------------------------------------
    if (Test-EXOAvailable -CmdletName 'Get-SafeAttachmentPolicy') {
        try {
            $saPolices      = @(Get-SafeAttachmentPolicy -ErrorAction Stop)
            $saRules        = @(Get-SafeAttachmentRule -ErrorAction Stop)
            $enabledSARules = @($saRules | Where-Object { $_.State -eq 'Enabled' })

            $def003Status = if ($enabledSARules.Count -gt 0) { 'PASS' } else { 'HIGH' }
            $saWithBlock   = @($saPolices | Where-Object { $_.Action -in @('Block', 'DynamicDelivery') })
            $def003Detail  = "Safe Attachment policies: $($saPolices.Count). Enabled rules: $($enabledSARules.Count). " +
                             "Policies with Block or DynamicDelivery action: $($saWithBlock.Count)."

            if ($saPolices.Count -gt 0 -and $saWithBlock.Count -eq 0) {
                $def003Status = 'HIGH'
                $def003Detail += ' No policies use Block or DynamicDelivery — attachments may not be inspected.'
            }

            $results.Add((New-CheckResult `
                -CheckId 'DEF-003' `
                -Category 'EmailSecurity' `
                -Name 'Defender: Safe Attachments Policy' `
                -Status $def003Status `
                -Detail $def003Detail `
                -Recommendation 'Create a Safe Attachments policy covering all domains with Action=DynamicDelivery (or Block). Enable Safe Attachments for SharePoint, OneDrive, and Teams in the global settings.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-attachments-policies-configure' `
                -CISControl 'CIS M365 6.4' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E5' `
                -AffectedObjects $(if ($def003Status -ne 'PASS') { @('Safe Attachments not configured') } else { @() })))
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'DEF-003' `
                -Category 'EmailSecurity' `
                -Name 'Defender: Safe Attachments Policy' `
                -Status 'INFO' `
                -Detail "Safe Attachments cmdlets returned an error — verify Defender for Office 365 P1/P2 (E5) license. Error: $_" `
                -Recommendation 'Ensure Defender for Office 365 P1 or P2 is licensed. Reconnect and retry.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-attachments-policies-configure' `
                -CISControl 'CIS M365 6.4' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E5' `
                -AffectedObjects @()))
        }
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'DEF-003' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Safe Attachments Policy' `
            -Status 'INFO' `
            -Detail 'Get-SafeAttachmentPolicy cmdlet not available. Safe Attachments requires Defender for Office 365 P1 or P2 (included in Microsoft 365 E5 / Business Premium).' `
            -Recommendation 'License Defender for Office 365 and run this check with an EXO-connected session.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-attachments-policies-configure' `
            -CISControl 'CIS M365 6.4' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEF-004: Safe Links
    # -------------------------------------------------------------------------
    if (Test-EXOAvailable -CmdletName 'Get-SafeLinksPolicy') {
        try {
            $slPolicies     = @(Get-SafeLinksPolicy -ErrorAction Stop)
            $slRules        = @(Get-SafeLinksRule -ErrorAction Stop)
            $enabledSLRules = @($slRules | Where-Object { $_.State -eq 'Enabled' })

            $def004Status   = if ($enabledSLRules.Count -gt 0) { 'PASS' } else { 'HIGH' }
            $slClickThrough = @($slPolicies | Where-Object { $_.AllowClickThrough -eq $true })
            $def004Detail   = "Safe Links policies: $($slPolicies.Count). Enabled rules: $($enabledSLRules.Count). " +
                              "Policies with AllowClickThrough=True (users can bypass warnings): $($slClickThrough.Count)."

            if ($slClickThrough.Count -gt 0) {
                $def004Status = 'HIGH'
                $def004Detail += ' AllowClickThrough should be disabled so users cannot click past Safe Links warnings.'
            }

            $results.Add((New-CheckResult `
                -CheckId 'DEF-004' `
                -Category 'EmailSecurity' `
                -Name 'Defender: Safe Links Policy' `
                -Status $def004Status `
                -Detail $def004Detail `
                -Recommendation 'Create a Safe Links policy covering all users. Set AllowClickThrough=False, TrackClicks=True, EnableForInternalSenders=True. Enable Safe Links for Microsoft Teams.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-links-policies-configure' `
                -CISControl 'CIS M365 6.5' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E5' `
                -AffectedObjects $($slClickThrough | ForEach-Object { $_.Name })))
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'DEF-004' `
                -Category 'EmailSecurity' `
                -Name 'Defender: Safe Links Policy' `
                -Status 'INFO' `
                -Detail "Safe Links cmdlets returned an error. Error: $_" `
                -Recommendation 'Ensure Defender for Office 365 P1 or P2 is licensed and EXO is connected.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-links-policies-configure' `
                -CISControl 'CIS M365 6.5' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E5' `
                -AffectedObjects @()))
        }
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'DEF-004' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Safe Links Policy' `
            -Status 'INFO' `
            -Detail 'Get-SafeLinksPolicy cmdlet not available. Safe Links requires Defender for Office 365 P1 or P2.' `
            -Recommendation 'License Defender for Office 365 and run this check with an EXO-connected session.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-links-policies-configure' `
            -CISControl 'CIS M365 6.5' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEF-005: Anti-malware policy
    # -------------------------------------------------------------------------
    try {
        $malwarePolicies = @(Get-MalwareFilterPolicy -ErrorAction Stop)
        $defaultMalware  = $malwarePolicies | Where-Object { $_.IsDefault -eq $true }
        $customMalware   = @($malwarePolicies | Where-Object { $_.IsDefault -ne $true })

        $noFileFilter = @($malwarePolicies | Where-Object { $_.EnableFileFilter -ne $true })
        $def005Status = if ($customMalware.Count -gt 0 -and $noFileFilter.Count -eq 0) { 'PASS' }
                        elseif ($noFileFilter.Count -gt 0) { 'HIGH' }
                        else { 'MEDIUM' }

        $def005Detail = "Anti-malware policies: $($malwarePolicies.Count) ($($customMalware.Count) custom). " +
                        "Policies without EnableFileFilter: $($noFileFilter.Count)."
        if ($noFileFilter.Count -gt 0) {
            $def005Detail += ' File type filtering (common attachment types) is not enabled on all policies — dangerous file types may pass through.'
        }
        if ($customMalware.Count -eq 0) {
            $def005Detail += ' No custom anti-malware policy. Relying on default policy settings only.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEF-005' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Anti-Malware Policy' `
            -Status $def005Status `
            -Detail $def005Detail `
            -Recommendation 'Create a custom anti-malware policy with EnableFileFilter=True, covering executable and script file extensions. Enable ZAP (zero-hour auto purge) for malware.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-malware-policies-configure' `
            -CISControl 'CIS M365 6.6' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects $($noFileFilter | ForEach-Object { $_.Name })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEF-005' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Anti-Malware Policy' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-malware-policies-configure' `
            -CISControl 'CIS M365 6.6' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEF-006: Outbound anti-spam policy
    # -------------------------------------------------------------------------
    try {
        $outboundSpamPolicies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)
        $defaultOutbound      = $outboundSpamPolicies | Where-Object { $_.IsDefault -eq $true }
        $customOutbound       = @($outboundSpamPolicies | Where-Object { $_.IsDefault -ne $true })

        $noActionOnThreshold = @($outboundSpamPolicies | Where-Object {
            $_.ActionWhenThresholdReached -notin @('BlockUserForToday', 'Alert', 'BlockUser')
        })

        $def006Status = if ($customOutbound.Count -gt 0) { 'PASS' } else { 'MEDIUM' }
        $def006Detail = "Outbound spam policies: $($outboundSpamPolicies.Count) ($($customOutbound.Count) custom). " +
                        "Default policy RecipientLimitExternalPerHour: $($defaultOutbound.RecipientLimitExternalPerHour). " +
                        "ActionWhenThresholdReached: $($defaultOutbound.ActionWhenThresholdReached)."
        if ($customOutbound.Count -eq 0) {
            $def006Detail += ' No custom outbound spam policy — exfiltration via high-volume sending may not be detected promptly.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEF-006' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Outbound Anti-Spam Policy' `
            -Status $def006Status `
            -Detail $def006Detail `
            -Recommendation 'Configure a custom outbound spam policy with RecipientLimitExternalPerHour set to a reasonable value (e.g. 500) and ActionWhenThresholdReached=BlockUserForToday. Add notifications to security team for user blocks.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-configure' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects $(if ($customOutbound.Count -eq 0) { @('No custom outbound spam policy') } else { @() })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEF-006' `
            -Category 'EmailSecurity' `
            -Name 'Defender: Outbound Anti-Spam Policy' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-configure' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEF-007: Preset security policies (Standard/Strict)
    # -------------------------------------------------------------------------
    $presetStandard = $false
    $presetStrict   = $false

    if (Test-EXOAvailable -CmdletName 'Get-EOPProtectionPolicyRule') {
        try {
            $eopRules       = @(Get-EOPProtectionPolicyRule -ErrorAction Stop)
            $presetStandard = [bool]($eopRules | Where-Object { $_.Identity -like '*Standard*' -and $_.State -eq 'Enabled' })
            $presetStrict   = [bool]($eopRules | Where-Object { $_.Identity -like '*Strict*' -and $_.State -eq 'Enabled' })
        }
        catch {
            Write-Verbose "DEF-007: Get-EOPProtectionPolicyRule failed: $_"
        }
    }

    $def007Detail = "Standard preset policy enabled: $presetStandard. Strict preset policy enabled: $presetStrict."
    if (-not $presetStandard -and -not $presetStrict) {
        $def007Detail += ' Neither Standard nor Strict preset security policies are enabled. Preset policies provide Microsoft-managed baseline protection that is automatically updated.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'DEF-007' `
        -Category 'EmailSecurity' `
        -Name 'Defender: Preset Security Policy Adoption' `
        -Status 'INFO' `
        -Detail $def007Detail `
        -Recommendation 'Consider applying the Standard or Strict preset security policy to all users as a baseline. Preset policies are maintained by Microsoft and automatically include new protections. Custom policies can coexist for targeted high-priority groups.' `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/preset-security-policies' `
        -CISControl '' `
        -SC300Domain 'Email Security' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
