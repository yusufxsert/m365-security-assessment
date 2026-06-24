#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Exchange Online mail flow rules, forwarding, and connector configuration.

.DESCRIPTION
    Test-MailFlow evaluates transport rules that could bypass security filtering, IP/domain
    allow-listing in connection filters, external auto-forwarding posture, the default remote
    domain AutoForward setting, and inbound/outbound connector security.

    All checks use Exchange Online PowerShell cmdlets with graceful fallback if EXO is
    unavailable. All findings are returned as PSCustomObject via New-CheckResult.
    No tenant state is modified.

.NOTES
    Required Permissions : ExchangeOnlineManagement module + EXO connection
    License Required     : E3 minimum
    Module               : Microsoft.Graph.Authentication (auth), ExchangeOnlineManagement (checks)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        MFL-001  Transport rules that bypass spam/malware filtering
        MFL-002  IP/domain allow-listing (connection filter)
        MFL-003  External mail forwarding allowed (remote domains + mailbox rules)
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
            -Detail 'ExchangeOnlineManagement cmdlets are not available. All mail flow checks require an active Exchange Online session. Run: Connect-Assessment -ConnectExchange.' `
            -Recommendation 'Connect to Exchange Online using Connect-Assessment -ConnectExchange to enable mail flow security checks.' `
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

        # Rules that set SCL to -1 (bypass spam) with no sender restriction
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
                # No sender restriction — applies to any sender including external
                $bypassRules.Add($ruleLabel)
            }
            elseif ($rule.FromScope -eq 'NotInOrganization' -or
                    ($rule.FromScope -ne 'InOrganization' -and -not $hasSenderRestriction)) {
                $bypassExternalRules.Add($ruleLabel)
            }
        }

        # Rules that bypass malware filtering
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

            # Check for large IP ranges in allow list
            $broadRanges = @($ipAllowList | Where-Object {
                # Flag /8, /16, /24 and single IPs in public ranges
                $_ -match '/[0-9]$' -or       # /0 - /9 (very broad)
                $_ -match '/1[0-5]$'            # /10 - /15 (still very broad)
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
    # MFL-003: External mail forwarding (remote domains + optional mailbox check)
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

        # Optionally check Graph for user-level mailbox forwarding (best-effort)
        try {
            # GET /users?$select=userPrincipalName,mailboxSettings is limited; use Graph only if possible
            $fwUsersResp = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/users?`$select=userPrincipalName,mailNickname&`$filter=assignedLicenses/any()&`$top=5" `
                -ErrorAction Stop
            # Only a sampling note — full mailbox forwarding check requires EXO Get-Mailbox
            if ($Detailed) {
                $results.Add((New-CheckResult `
                    -CheckId 'MFL-003' `
                    -Category 'EmailSecurity' `
                    -Name 'Mail Flow: Per-User Mailbox Forwarding (Sampling Note)' `
                    -Status 'INFO' `
                    -Detail 'Per-user mailbox forwarding rules require Exchange Online: Get-Mailbox -Filter {ForwardingSmtpAddress -ne $null}. Graph API does not expose mailbox forwarding settings via v1.0.' `
                    -Recommendation 'Run: Get-Mailbox -Filter {ForwardingSmtpAddress -ne $null} | Select DisplayName,ForwardingSmtpAddress,DeliverToMailboxAndForward to identify user-level forwarding rules.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }
        catch {
            Write-Verbose "MFL-003: Graph user mailbox check unavailable: $_"
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

        # Inbound connector checks
        $weakCertInbound = [System.Collections.Generic.List[string]]::new()
        foreach ($conn in $inboundConnectors) {
            # RequireTls should be True; if ConnectorType is Partner, TlsSenderCertificateName should be set
            $noTls   = $conn.RequireTls -ne $true
            $noCert  = ($conn.ConnectorType -eq 'Partner' -and
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

        # Outbound connector inventory
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
