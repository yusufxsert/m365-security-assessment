#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Microsoft Defender for Office 365 policy configuration.

.DESCRIPTION
    Test-DefenderO365 evaluates anti-phishing, Safe Attachments, Safe Links, anti-malware,
    outbound anti-spam, and preset security policy adoption. All checks use Exchange Online
    PowerShell cmdlets (Get-AntiPhishPolicy, Get-SafeAttachmentPolicy, etc.) with a Microsoft
    Graph Secure Score fallback for environments where EXO is unavailable.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

.NOTES
    Required Permissions : ExchangeOnlineManagement module + EXO connection (preferred)
                           OR SecurityEvents.Read.All for Secure Score fallback
    License Required     : E3 for anti-phishing, anti-malware, anti-spam
                           E5 / Defender for Office 365 P1 for Safe Attachments and Safe Links
    Module               : Microsoft.Graph.Authentication, ExchangeOnlineManagement (optional)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        DEF-001  Anti-phishing policy configured and key features enabled
        DEF-002  Anti-phishing impersonation protection targets
        DEF-003  Safe Attachments policy (requires E5 / Defender P1)
        DEF-004  Safe Links policy (requires E5 / Defender P1)
        DEF-005  Anti-malware policy
        DEF-006  Outbound anti-spam policy
        DEF-007  Preset security policies (Standard/Strict) adoption
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/EmailSecurity/Test-DefenderO365.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
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
        # Emit one informational note that EXO isn't available, then attempt Graph fallback per check
        $results.Add((New-CheckResult `
            -CheckId 'DEF-000' `
            -Category 'EmailSecurity' `
            -Name 'Defender O365: Exchange Online Connection' `
            -Status 'INFO' `
            -Detail 'ExchangeOnlineManagement module cmdlets are not available in this session. Attempting Microsoft Graph Secure Score fallback for applicable checks. For full fidelity, run: Connect-Assessment -ConnectExchange.' `
            -Recommendation 'Connect Exchange Online using Connect-Assessment -ConnectExchange for complete Defender for Office 365 policy assessment.' `
            -Reference 'https://learn.microsoft.com/powershell/exchange/connect-to-exchange-online-powershell' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # Graph Secure Score lookup (used as fallback and supplement)
    # -------------------------------------------------------------------------
    $secureScoreControls = @{}
    try {
        $ssResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=200' `
            -ErrorAction Stop
        foreach ($ctrl in $ssResp.value) {
            $secureScoreControls[$ctrl.controlName] = $ctrl
        }
    }
    catch {
        Write-Verbose "DEF: Secure Score unavailable: $_"
    }

    # -------------------------------------------------------------------------
    # DEF-001: Anti-phishing policy
    # -------------------------------------------------------------------------
    if ($exoConnected) {
        try {
            $antiPhishPolicies = @(Get-AntiPhishPolicy -ErrorAction Stop)
            $antiPhishRules    = @(Get-AntiPhishRule -ErrorAction Stop)

            $defaultPolicy = $antiPhishPolicies | Where-Object { $_.IsDefault -eq $true }
            $customPolicies = $antiPhishPolicies | Where-Object { $_.IsDefault -ne $true }

            # Check key settings on all policies (default + custom)
            $mailboxIntelMissing   = @($antiPhishPolicies | Where-Object { $_.EnableMailboxIntelligence -ne $true })
            $spoofIntelMissing     = @($antiPhishPolicies | Where-Object { $_.EnableSpoofIntelligence -ne $true })

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

        # -----------------------------------------------------------------
        # DEF-002: Impersonation protection targets
        # -----------------------------------------------------------------
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

        # -----------------------------------------------------------------
        # DEF-003: Safe Attachments
        # -----------------------------------------------------------------
        if (Test-EXOAvailable -CmdletName 'Get-SafeAttachmentPolicy') {
            try {
                $saPolices = @(Get-SafeAttachmentPolicy -ErrorAction Stop)
                $saRules   = @(Get-SafeAttachmentRule -ErrorAction Stop)
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

        # -----------------------------------------------------------------
        # DEF-004: Safe Links
        # -----------------------------------------------------------------
        if (Test-EXOAvailable -CmdletName 'Get-SafeLinksPolicy') {
            try {
                $slPolicies  = @(Get-SafeLinksPolicy -ErrorAction Stop)
                $slRules     = @(Get-SafeLinksRule -ErrorAction Stop)
                $enabledSLRules = @($slRules | Where-Object { $_.State -eq 'Enabled' })

                $def004Status    = if ($enabledSLRules.Count -gt 0) { 'PASS' } else { 'HIGH' }
                $slClickThrough  = @($slPolicies | Where-Object { $_.AllowClickThrough -eq $true })
                $def004Detail    = "Safe Links policies: $($slPolicies.Count). Enabled rules: $($enabledSLRules.Count). " +
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

        # -----------------------------------------------------------------
        # DEF-005: Anti-malware policy
        # -----------------------------------------------------------------
        try {
            $malwarePolicies = @(Get-MalwareFilterPolicy -ErrorAction Stop)
            $defaultMalware  = $malwarePolicies | Where-Object { $_.IsDefault -eq $true }
            $customMalware   = @($malwarePolicies | Where-Object { $_.IsDefault -ne $true })

            # Check file filter enabled on all policies
            $noFileFilter  = @($malwarePolicies | Where-Object { $_.EnableFileFilter -ne $true })
            $def005Status  = if ($customMalware.Count -gt 0 -and $noFileFilter.Count -eq 0) { 'PASS' }
                             elseif ($noFileFilter.Count -gt 0) { 'HIGH' }
                             else { 'MEDIUM' }

            $def005Detail  = "Anti-malware policies: $($malwarePolicies.Count) ($($customMalware.Count) custom). " +
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

        # -----------------------------------------------------------------
        # DEF-006: Outbound anti-spam policy
        # -----------------------------------------------------------------
        try {
            $outboundSpamPolicies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction Stop)
            $defaultOutbound      = $outboundSpamPolicies | Where-Object { $_.IsDefault -eq $true }
            $customOutbound       = @($outboundSpamPolicies | Where-Object { $_.IsDefault -ne $true })

            # Key settings: RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, ActionWhenThresholdReached
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

        # -----------------------------------------------------------------
        # DEF-007: Preset security policies (Standard/Strict)
        # -----------------------------------------------------------------
        # Preset policies are reflected as special named protection policies
        # Check via Get-EOPProtectionPolicyRule and Get-ATPProtectionPolicyRule
        $presetStandard = $false
        $presetStrict   = $false

        if (Test-EXOAvailable -CmdletName 'Get-EOPProtectionPolicyRule') {
            try {
                $eopRules = @(Get-EOPProtectionPolicyRule -ErrorAction Stop)
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
    }
    else {
        # -------------------------------------------------------------------------
        # EXO not available — Graph Secure Score fallback for DEF-001 through DEF-007
        # -------------------------------------------------------------------------
        if ($secureScoreControls.Count -eq 0) {
            foreach ($checkId in @('DEF-001','DEF-002','DEF-003','DEF-004','DEF-005','DEF-006','DEF-007')) {
                $results.Add((New-CheckResult `
                    -CheckId $checkId `
                    -Category 'EmailSecurity' `
                    -Name "Defender O365: Check $checkId" `
                    -Status 'INFO' `
                    -Detail 'Check skipped: Exchange Online not connected and Graph Secure Score is unavailable. Required: ExchangeOnlineManagement session OR SecurityEvents.Read.All.' `
                    -Recommendation 'Connect Exchange Online (Connect-Assessment -ConnectExchange) for complete assessment.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
            return $results
        }

        # Map Secure Score control names to our check IDs
        $scoreCheckMap = @{
            'DEF-001' = @('EnableAntiPhishPolicy', 'AntiPhishPolicy')
            'DEF-002' = @('AntiPhishPolicyImpersonation')
            'DEF-003' = @('EnableSafeAttachmentForSPOTeamsODB', 'SafeAttachmentForEmail')
            'DEF-004' = @('EnableSafeLinksForEmail', 'SafeLinksForEmail')
            'DEF-005' = @('MalwareFilterPolicy', 'EnableMalwareFilterPolicy')
            'DEF-006' = @('OutboundSpamPolicy')
            'DEF-007' = @('PresetSecurityPolicy')
        }

        $referenceMap = @{
            'DEF-001' = 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies-about'
            'DEF-002' = 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-phishing-policies-about'
            'DEF-003' = 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-attachments-policies-configure'
            'DEF-004' = 'https://learn.microsoft.com/microsoft-365/security/office-365-security/safe-links-policies-configure'
            'DEF-005' = 'https://learn.microsoft.com/microsoft-365/security/office-365-security/anti-malware-policies-configure'
            'DEF-006' = 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-configure'
            'DEF-007' = 'https://learn.microsoft.com/microsoft-365/security/office-365-security/preset-security-policies'
        }

        $licenseMap = @{
            'DEF-003' = 'E5'
            'DEF-004' = 'E5'
        }

        foreach ($checkId in $scoreCheckMap.Keys) {
            $candidateControls = @()
            foreach ($ctrlName in $scoreCheckMap[$checkId]) {
                $matchedCtrl = $secureScoreControls.Values | Where-Object {
                    $_.controlName -like "*$ctrlName*" -or $_.title -like "*$ctrlName*"
                }
                if ($matchedCtrl) { $candidateControls += $matchedCtrl }
            }

            if ($candidateControls.Count -gt 0) {
                $ctrl = $candidateControls | Select-Object -First 1
                $implStatus = $ctrl.implementationStatus
                $status = switch ($implStatus) {
                    'implemented'    { 'PASS' }
                    'thirdParty'     { 'PASS' }
                    'notImplemented' { 'HIGH' }
                    default          { 'INFO' }
                }
                $detail = "Secure Score control '$($ctrl.controlName)' — status: $implStatus. Title: $($ctrl.title)."
            }
            else {
                $status = 'INFO'
                $detail = "No matching Secure Score control found for $checkId. Connect Exchange Online for full assessment."
            }

            $results.Add((New-CheckResult `
                -CheckId $checkId `
                -Category 'EmailSecurity' `
                -Name "Defender O365: $checkId (Secure Score Fallback)" `
                -Status $status `
                -Detail $detail `
                -Recommendation 'Connect Exchange Online for detailed policy inspection. Secure Score provides indicative status only.' `
                -Reference $referenceMap[$checkId] `
                -CISControl '' `
                -SC300Domain 'Email Security' `
                -LicenseRequired $(if ($licenseMap.ContainsKey($checkId)) { $licenseMap[$checkId] } else { 'E3' }) `
                -AffectedObjects @()))
        }
    }

    return $results
}
