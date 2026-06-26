#Requires -Version 7.0

<#
.SYNOPSIS
    Audits Exchange Online mail flow rules, forwarding, and connector configuration (PS-only variant).

.DESCRIPTION
    PS-ONLY VARIANT — No App Registration required.

    Test-MailFlow evaluates transport rules that could bypass security filtering, IP/domain
    allow-listing in connection filters, external auto-forwarding posture, the default remote
    domain AutoForward setting, and inbound/outbound connector security.

    All checks use Exchange Online PowerShell cmdlets exclusively. The original script contained
    a best-effort Graph call for per-user mailbox forwarding sampling; in this PS-only version
    that check is replaced by Get-Mailbox (EXO cmdlet), which gives full fidelity without Graph.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

.NOTES
    ---- PS-ONLY VARIANT ----
    WHY PS-ONLY:
        The original script (modules/EmailSecurity/Test-MailFlow.ps1) used Invoke-MgGraphRequest
        for a best-effort per-user mailbox forwarding sample (MFL-003). This PS-only version
        replaces that with Get-Mailbox -Filter, which gives complete coverage without any Graph
        dependency. All other checks were already EXO-only and are unchanged.

    SEE ALSO (Graph/App-Registration variant):
        scripts/modules/EmailSecurity/Test-MailFlow.ps1

    Required Connection  : Connect-ExchangeOnline
                           (Run Connect-PSOnly.ps1 or: Connect-ExchangeOnline -UserPrincipalName <UPN>)
    Required Module      : ExchangeOnlineManagement
    Cmdlets Used         : Get-TransportRule
                           Get-HostedConnectionFilterPolicy
                           Get-RemoteDomain
                           Get-InboundConnector
                           Get-OutboundConnector
                           Get-Mailbox (MFL-003 per-user forwarding check)

    License Required     : E3 minimum

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        MFL-001  Transport rules that bypass spam/malware filtering
        MFL-002  IP/domain allow-listing (connection filter)
        MFL-003  External mail forwarding allowed (remote domains + per-mailbox forwarding rules)
        MFL-004  AutoForwardEnabled on Default remote domain
        MFL-005  Connector configuration (inbound / outbound)
#>

function Test-MailFlow {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Check EXO availability
    # -------------------------------------------------------------------------
    $exoAvailable = [bool](Get-Command -Name 'Get-TransportRule' -ErrorAction SilentlyContinue)

    if (-not $exoAvailable) {
        $results.Add((New-CheckResult `
            -CheckId 'MFL-000' `
            -Category 'EmailSecurity' `
            -Name 'Mail Flow: Exchange Online Connection' `
            -Status 'INFO' `
            -Detail 'ExchangeOnlineManagement cmdlets are not available. All mail flow checks require an active Exchange Online session. Run: Connect-ExchangeOnline -UserPrincipalName <UPN>' `
            -Recommendation 'Connect to Exchange Online using Connect-ExchangeOnline to enable mail flow security checks.' `
            -Reference 'https://learn.microsoft.com/powershell/exchange/connect-to-exchange-online-powershell' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # MFL-001: Transport rules bypassing spam/malware filtering
    # -------------------------------------------------------------------------
    try {
        $allRules = @(Get-TransportRule -ErrorAction Stop)

        $bypassRules         = [System.Collections.Generic.List[string]]::new()
        $bypassExternalRules = [System.Collections.Generic.List[string]]::new()

        foreach ($rule in $allRules) {
            if ($rule.SetSCL -ne -1) { continue }

            $hasSenderRestriction = $rule.FromScope -eq 'InOrganization' -or
                                    $rule.From.Count -gt 0 -or
                                    $rule.FromMemberOf.Count -gt 0 -or
                                    $rule.SenderIPRanges.Count -gt 0 -or
                                    $rule.SenderDomainIs.Count -gt 0

            $ruleLabel = "$($rule.Name) [priority: $($rule.Priority), state: $($rule.State)]"

            if (-not $hasSenderRestriction) {
                $bypassRules.Add($ruleLabel)
            }
            elseif ($rule.FromScope -eq 'NotInOrganization' -or
                    ($rule.FromScope -ne 'InOrganization' -and -not $hasSenderRestriction)) {
                $bypassExternalRules.Add($ruleLabel)
            }
        }

        $malwareBypassRules = @($allRules | Where-Object {
            $_.SetHeaderName -like '*X-MS-Exchange-Organization-SCL*' -or
            $_.BypassSpamFiltering -eq $true
        })

        if ($bypassRules.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-001' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Transport Rules Bypassing Spam Filtering (No Sender Restriction)' `
                -Status 'CRITICAL' `
                -Detail "Found $($bypassRules.Count) transport rule(s) that set SCL=-1 without any sender restriction. These rules effectively bypass spam filtering for ALL incoming email, including external senders." `
                -Recommendation 'Review each rule immediately. If bypass is required for a trusted system (e.g. on-premises relay), restrict by sender IP range, authenticated domain, or specific sender address. Remove or restrict unrestricted bypass rules.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/step-by-step-guides/optimize-and-correct-security-policies-with-configuration-analyzer' `
                -CISControl 'CIS M365 6.7' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects $bypassRules.ToArray()))
        }

        if ($bypassExternalRules.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-001' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Transport Rules Bypassing Spam Filtering (External Senders)' `
                -Status 'HIGH' `
                -Detail "Found $($bypassExternalRules.Count) transport rule(s) that set SCL=-1 for external senders. These rules trust external senders explicitly and bypass Microsoft spam filtering." `
                -Recommendation 'Restrict these rules to trusted, specific sender IP ranges or authenticated connectors rather than allowing external domains broadly.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/step-by-step-guides/optimize-and-correct-security-policies-with-configuration-analyzer' `
                -CISControl 'CIS M365 6.7' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects $bypassExternalRules.ToArray()))
        }

        if ($bypassRules.Count -eq 0 -and $bypassExternalRules.Count -eq 0) {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-001' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Transport Rules — Bypass Check' `
                -Status 'PASS' `
                -Detail "No unrestricted spam-bypass transport rules found. Total transport rules: $($allRules.Count)." `
                -Recommendation 'Periodically audit transport rules when new rules are added by administrators or third-party integrations.' `
                -Reference 'https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules' `
                -CISControl 'CIS M365 6.7' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }

        if ($Detailed) {
            foreach ($rule in $allRules | Where-Object { $_.State -eq 'Enabled' }) {
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-001' `
                    -Category 'EmailSecurity' `
                    -Name "Mail Flow Rule Detail: $($rule.Name)" `
                    -Status 'INFO' `
                    -Detail "Priority: $($rule.Priority) | SCL: $($rule.SetSCL) | BypassSpam: $($rule.BypassSpamFiltering) | FromScope: $($rule.FromScope) | SenderDomainIs: $($rule.SenderDomainIs -join ',') | From: $($rule.From -join ',')" `
                    -Recommendation '' `
                    -Reference 'https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MFL-001' `
            -Category 'EmailSecurity' `
            -Name 'Mail Flow: Transport Rules Bypass Check' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules' `
            -CISControl 'CIS M365 6.7' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MFL-002: Allowed sender IPs and domain allow-listing
    # -------------------------------------------------------------------------
    try {
        $connFilterPolicies = @(Get-HostedConnectionFilterPolicy -ErrorAction Stop)

        foreach ($policy in $connFilterPolicies) {
            $ipAllowList     = @($policy.IPAllowList)
            $domainAllowList = @($policy.AllowedSenderDomains)

            $broadRanges = @($ipAllowList | Where-Object {
                $_ -match '/[0-9]$' -or
                $_ -match '/1[0-5]$'
            })

            if ($broadRanges.Count -gt 0) {
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-002' `
                    -Category 'EmailSecurity' `
                    -Name "Mail Flow: Large IP Ranges in Connection Allow List ($($policy.Name))" `
                    -Status 'HIGH' `
                    -Detail "Connection filter policy '$($policy.Name)' has $($ipAllowList.Count) IP(s) in allow list, including potentially broad ranges: $($broadRanges -join ', '). IPs on this list bypass spam filtering." `
                    -Recommendation 'Review and minimise the IP allow list. Use the narrowest possible CIDR ranges for trusted senders. Remove any IP ranges that are no longer needed.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/connection-filter-policies-configure' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $broadRanges))
            }
            elseif ($ipAllowList.Count -gt 0) {
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-002' `
                    -Category 'EmailSecurity' `
                    -Name "Mail Flow: IP Allow List Present ($($policy.Name))" `
                    -Status 'LOW' `
                    -Detail "Connection filter policy '$($policy.Name)' has $($ipAllowList.Count) IP(s) in allow list. These IPs bypass spam filtering. IPs: $($ipAllowList -join ', ')." `
                    -Recommendation 'Review the IP allow list periodically. Prefer authenticating connectors over IP allow-listing.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/connection-filter-policies-configure' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $ipAllowList))
            }

            if ($domainAllowList.Count -ge 5) {
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-002' `
                    -Category 'EmailSecurity' `
                    -Name "Mail Flow: Domain Allow List Too Permissive ($($policy.Name))" `
                    -Status 'MEDIUM' `
                    -Detail "Connection filter policy '$($policy.Name)' has $($domainAllowList.Count) domains in the allowed senders list. Allowed sender domains bypass spam filtering. Domains: $($domainAllowList -join ', ')." `
                    -Recommendation 'Reduce the domain allow list to only verified business-critical senders. Use mail flow rules with more precise conditions instead of blanket domain allow-listing.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/connection-filter-policies-configure' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $domainAllowList))
            }

            if ($ipAllowList.Count -eq 0 -and $domainAllowList.Count -lt 5 -and $broadRanges.Count -eq 0) {
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-002' `
                    -Category 'EmailSecurity' `
                    -Name "Mail Flow: Connection Filter Allow List ($($policy.Name))" `
                    -Status 'PASS' `
                    -Detail "Connection filter policy '$($policy.Name)' — IP allow list: $($ipAllowList.Count) entries. Domain allow list: $($domainAllowList.Count) entries. No overly permissive allow-listing detected." `
                    -Recommendation 'Continue auditing connection filter policies when adding new partner integrations.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/connection-filter-policies-configure' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MFL-002' `
            -Category 'EmailSecurity' `
            -Name 'Mail Flow: Connection Filter Policy' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/connection-filter-policies-configure' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MFL-003: External mail forwarding (remote domains + per-mailbox forwarding)
    # -------------------------------------------------------------------------
    try {
        $remoteDomains = @(Get-RemoteDomain -ErrorAction Stop)
        $defaultDomain = $remoteDomains | Where-Object { $_.DomainName -eq '*' }
        $autoFwEnabled = @($remoteDomains | Where-Object {
            $_.AutoForwardEnabled -eq $true -and $_.DomainName -ne '*'
        })

        if ($autoFwEnabled.Count -gt 0) {
            $fwDomainNames = @($autoFwEnabled | ForEach-Object { "$($_.DomainName) [AutoForwardEnabled: True]" })
            $results.Add((New-CheckResult `
                -CheckId 'MFL-003' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: External Auto-Forwarding Allowed to Specific Domains' `
                -Status 'HIGH' `
                -Detail "Found $($autoFwEnabled.Count) remote domain(s) with AutoForwardEnabled=True. Auto-forwarding to these external domains is explicitly permitted and could be used for data exfiltration." `
                -Recommendation 'Review each remote domain with AutoForwardEnabled. Disable auto-forwarding unless there is a documented and approved business reason. Enforce via outbound anti-spam policy and transport rules.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                -CISControl 'CIS M365 6.8' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects $fwDomainNames))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-003' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: External Auto-Forwarding (Remote Domain Config)' `
                -Status 'PASS' `
                -Detail "No specific remote domains have AutoForwardEnabled=True. Checked $($remoteDomains.Count) remote domain entries." `
                -Recommendation 'Continue auditing remote domain settings. Combine with MFL-004 (Default remote domain AutoForwardEnabled) for complete coverage.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                -CISControl 'CIS M365 6.8' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }

        # PS-only: use Get-Mailbox to find per-user mailbox forwarding (replaces Graph sampling in original)
        try {
            $forwardingMailboxes = @(Get-Mailbox -ResultSize Unlimited -Filter {
                ForwardingSmtpAddress -ne $null
            } -ErrorAction Stop)

            if ($forwardingMailboxes.Count -gt 0) {
                $fwDetails = @($forwardingMailboxes | ForEach-Object {
                    "$($_.PrimarySmtpAddress) -> $($_.ForwardingSmtpAddress) [DeliverAndForward: $($_.DeliverToMailboxAndForward)]"
                })
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-003' `
                    -Category 'EmailSecurity' `
                    -Name 'Mail Flow: Per-Mailbox External Forwarding Rules' `
                    -Status 'HIGH' `
                    -Detail "$($forwardingMailboxes.Count) mailbox(es) have ForwardingSmtpAddress configured. This forwards a copy (or all) email to an external address and is a common BEC exfiltration vector." `
                    -Recommendation 'Review each mailbox with ForwardingSmtpAddress. Remove unauthorised forwarding. Consider blocking user-set forwarding via transport rule: reject messages with SentToScope=NotInOrganization and ForwardingSmtpAddress set.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                    -CISControl 'CIS M365 6.8' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $fwDetails))
            }
            else {
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-003' `
                    -Category 'EmailSecurity' `
                    -Name 'Mail Flow: Per-Mailbox External Forwarding Rules' `
                    -Status 'PASS' `
                    -Detail 'No mailboxes have ForwardingSmtpAddress configured. Per-mailbox external forwarding is not in use.' `
                    -Recommendation 'Periodically re-run this check. BEC attackers often configure inbox rules or mailbox forwarding immediately after compromise.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                    -CISControl 'CIS M365 6.8' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-003' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Per-Mailbox External Forwarding Rules' `
                -Status 'INFO' `
                -Detail "Get-Mailbox forwarding check failed. Error: $_" `
                -Recommendation 'Verify Exchange Online connection and retry. Manual check: Get-Mailbox -ResultSize Unlimited -Filter {ForwardingSmtpAddress -ne $null}' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                -CISControl '' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MFL-003' `
            -Category 'EmailSecurity' `
            -Name 'Mail Flow: External Auto-Forwarding' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
            -CISControl 'CIS M365 6.8' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MFL-004: Default remote domain AutoForwardEnabled
    # -------------------------------------------------------------------------
    try {
        $defaultRemoteDomain = Get-RemoteDomain -Identity 'Default' -ErrorAction Stop

        if ($defaultRemoteDomain.AutoForwardEnabled -eq $true) {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-004' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Default Remote Domain Auto-Forwarding Enabled' `
                -Status 'HIGH' `
                -Detail "The Default remote domain (wildcard *) has AutoForwardEnabled=True. This allows all mailboxes to forward email to any external address without restriction. This is a common data exfiltration vector via BEC attacks." `
                -Recommendation "Set AutoForwardEnabled=False on the Default remote domain: Set-RemoteDomain -Identity Default -AutoForwardEnabled `$false. Then use transport rules or outbound anti-spam policy to block automatic forwarding at the policy level." `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                -CISControl 'CIS M365 6.8' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @('Default remote domain (*)')))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-004' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Default Remote Domain Auto-Forwarding' `
                -Status 'PASS' `
                -Detail "Default remote domain has AutoForwardEnabled=False. External auto-forwarding is blocked at the tenant level." `
                -Recommendation 'Verify the outbound anti-spam policy also blocks automatic forwarding (AutoForwardingMode=Off or On) for defense-in-depth.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                -CISControl 'CIS M365 6.8' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MFL-004' `
            -Category 'EmailSecurity' `
            -Name 'Mail Flow: Default Remote Domain Auto-Forwarding' `
            -Status 'INFO' `
            -Detail "Check skipped: could not retrieve Default remote domain settings. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
            -CISControl 'CIS M365 6.8' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MFL-005: Connector configuration (inbound / outbound)
    # -------------------------------------------------------------------------
    try {
        $inboundConnectors  = @(Get-InboundConnector  -ErrorAction Stop)
        $outboundConnectors = @(Get-OutboundConnector -ErrorAction Stop)

        $weakCertInbound = [System.Collections.Generic.List[string]]::new()
        foreach ($conn in $inboundConnectors) {
            $noTls  = $conn.RequireTls -ne $true
            $noCert = ($conn.ConnectorType -eq 'Partner' -and
                       (-not $conn.TlsSenderCertificateName -or $conn.TlsSenderCertificateName -eq ''))

            if ($noTls -or $noCert) {
                $label = "$($conn.Name) [RequireTls: $($conn.RequireTls), TlsCert: '$($conn.TlsSenderCertificateName)', Type: $($conn.ConnectorType)]"
                $weakCertInbound.Add($label)
            }
        }

        if ($weakCertInbound.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-005' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Inbound Connectors Without Certificate Validation' `
                -Status 'MEDIUM' `
                -Detail "Found $($weakCertInbound.Count) inbound connector(s) that do not require TLS or do not validate the sender certificate. This may allow spoofed inbound connections from unexpected sources." `
                -Recommendation 'For partner connectors, set RequireTls=True and configure TlsSenderCertificateName to the expected certificate subject. This prevents unauthorised systems from injecting mail via the connector.' `
                -Reference 'https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail' `
                -CISControl '' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects $weakCertInbound.ToArray()))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'MFL-005' `
                -Category 'EmailSecurity' `
                -Name 'Mail Flow: Inbound Connector Security' `
                -Status 'PASS' `
                -Detail "All $($inboundConnectors.Count) inbound connector(s) require TLS or are correctly configured. Connector names: $(@($inboundConnectors.Name) -join ', ')." `
                -Recommendation 'Review connector configurations after adding new partner integrations.' `
                -Reference 'https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail' `
                -CISControl '' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }

        $outboundDetail = if ($outboundConnectors.Count -gt 0) {
            $connList = @($outboundConnectors | ForEach-Object {
                "$($_.Name) [type: $($_.ConnectorType), TLS: $($_.TlsSettings), enabled: $($_.Enabled)]"
            })
            "Outbound connectors ($($outboundConnectors.Count)): $($connList -join '; ')."
        }
        else {
            'No outbound connectors configured (direct send via Exchange Online).'
        }

        $results.Add((New-CheckResult `
            -CheckId 'MFL-005' `
            -Category 'EmailSecurity' `
            -Name 'Mail Flow: Outbound Connector Inventory' `
            -Status 'INFO' `
            -Detail $outboundDetail `
            -Recommendation 'Ensure outbound connectors to partner systems use TlsSettings=EncryptionOnly or higher. Periodically review smart host configurations.' `
            -Reference 'https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @($outboundConnectors | ForEach-Object { $_.Name })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MFL-005' `
            -Category 'EmailSecurity' `
            -Name 'Mail Flow: Connector Configuration' `
            -Status 'INFO' `
            -Detail "Check skipped: EXO command failed. Error: $_" `
            -Recommendation 'Reconnect to Exchange Online and retry.' `
            -Reference 'https://learn.microsoft.com/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
