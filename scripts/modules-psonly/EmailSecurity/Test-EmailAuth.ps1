#Requires -Version 7.0

<#
.SYNOPSIS
    PS-only: Audits email authentication records (SPF, DKIM, DMARC) via EXO PowerShell.

.DESCRIPTION
    PowerShell-only variant of Test-EmailAuth. Instead of retrieving domains via
    Microsoft Graph (Invoke-MgGraphRequest → /domains), this version uses
    Get-AcceptedDomain from ExchangeOnlineManagement — a native EXO cmdlet that
    does not require a Graph App Registration.

    DNS checks (SPF/DKIM/DMARC/MX) are unchanged — they use Resolve-DnsName and
    are identical to the Graph variant.

    DKIM status uses Get-DkimSigningConfig (EXO) which is MORE accurate than the
    DNS-based CNAME fallback in the Graph version.

    WHY PS-ONLY
    -----------
    • No App Registration or service principal needed
    • Get-AcceptedDomain is available to any Exchange Administrator
    • Get-DkimSigningConfig provides authoritative DKIM state (not inferred from DNS)
    • Suitable for ad-hoc runs without infrastructure setup

    LIMITATION vs GRAPH VARIANT
    ----------------------------
    • Federation type (Managed vs Federated) uses Get-AcceptedDomain.DomainType
      which reflects the domain type but not the federation provider detail.
      For federation provider detail (issuerUri), use the Graph variant.

    See also: scripts/modules/EmailSecurity/Test-EmailAuth.ps1  (Graph variant)

.NOTES
    Required connection : Connect-ExchangeOnline -UserPrincipalName admin@contoso.com
    Module              : ExchangeOnlineManagement
    Cmdlets used        : Get-AcceptedDomain, Get-DkimSigningConfig, Resolve-DnsName
    License             : E3 minimum
    No tenant state is modified.

    Checks:
        EML-001  SPF record present and enforcing hard fail
        EML-002  DKIM configured and enabled (authoritative via Get-DkimSigningConfig)
        EML-003  DMARC record and policy strength
        EML-004  DMARC aggregate reporting (rua tag)
        EML-005  MX record pointing to Exchange Online
        EML-006  Domain type (Authoritative / Federated)
#>

function Test-EmailAuth {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve accepted domains via EXO (replaces Graph /domains call)
    # -------------------------------------------------------------------------
    $domains = @()
    try {
        $accepted = Get-AcceptedDomain -ErrorAction Stop
        # Only custom domains (exclude *.onmicrosoft.com) unless that is the only domain
        $customDomains = @($accepted | Where-Object { $_.DomainName -notlike '*.onmicrosoft.com' })
        $domains = if ($customDomains.Count -gt 0) { $customDomains } else { @($accepted) }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'EML-000' `
            -Category 'EmailSecurity' `
            -Name 'Domain Retrieval (EXO)' `
            -Status 'INFO' `
            -Detail "Could not retrieve accepted domains via Get-AcceptedDomain. Ensure Exchange Online is connected. Error: $_" `
            -Recommendation 'Run: Connect-ExchangeOnline -UserPrincipalName admin@contoso.com' `
            -Reference 'https://learn.microsoft.com/powershell/module/exchange/get-accepteddomain' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    if ($domains.Count -eq 0) {
        $results.Add((New-CheckResult `
            -CheckId 'EML-000' `
            -Category 'EmailSecurity' `
            -Name 'Domain Retrieval (EXO)' `
            -Status 'INFO' `
            -Detail 'No accepted domains found. Add and verify at least one custom domain before running email authentication checks.' `
            -Recommendation 'Add a custom domain in Microsoft 365 admin center.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/admin/setup/add-domain' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # Primary domain = the one marked Default
    $primaryDomain = $domains | Where-Object { $_.Default -eq $true } | Select-Object -First 1
    if (-not $primaryDomain) { $primaryDomain = $domains[0] }

    # -------------------------------------------------------------------------
    # Load DKIM configuration (authoritative EXO source — no DNS inference needed)
    # -------------------------------------------------------------------------
    $dkimMap = @{}
    try {
        $dkimConfigs = Get-DkimSigningConfig -ErrorAction Stop
        foreach ($cfg in $dkimConfigs) {
            $dkimMap[$cfg.Domain] = $cfg
        }
        Write-Verbose "Loaded DKIM config for $($dkimMap.Count) domain(s)."
    }
    catch {
        Write-Warning "Get-DkimSigningConfig failed — falling back to DNS-based DKIM check: $_"
    }

    # -------------------------------------------------------------------------
    # Per-domain checks
    # -------------------------------------------------------------------------
    foreach ($domain in $domains) {
        $domainName = $domain.DomainName.ToString()
        $isDefault  = $domain.Default -eq $true

        # --- EML-001: SPF ---
        try {
            $txtRecords = Resolve-DnsName -Name $domainName -Type TXT -ErrorAction Stop
            $spfRecord  = ($txtRecords | Where-Object { $_.Strings -match '^v=spf1' } |
                          Select-Object -First 1).Strings

            if (-not $spfRecord) {
                $results.Add((New-CheckResult `
                    -CheckId 'EML-001' `
                    -Category 'EmailSecurity' `
                    -Name "SPF: Record Missing ($domainName)" `
                    -Status (if ($isDefault) { 'CRITICAL' } else { 'HIGH' }) `
                    -Detail "No SPF TXT record found for $domainName. Without SPF, any server can send email claiming to be from this domain." `
                    -Recommendation "Publish an SPF record: v=spf1 include:spf.protection.outlook.com -all" `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-spf-configure' `
                    -CISControl 'CIS M365 6.1' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @($domainName)))
            }
            else {
                $spfText = $spfRecord -join ''

                if ($spfText -match '\+all') {
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-001' `
                        -Category 'EmailSecurity' `
                        -Name "SPF: Permissive '+all' ($domainName)" `
                        -Status 'HIGH' `
                        -Detail "SPF record uses '+all' — any sender passes SPF. Record: $spfText" `
                        -Recommendation "Replace '+all' with '-all' (hard fail). Example: v=spf1 include:spf.protection.outlook.com -all" `
                        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-spf-configure' `
                        -CISControl 'CIS M365 6.1' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @($domainName)))
                }
                elseif ($spfText -match '~all') {
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-001' `
                        -Category 'EmailSecurity' `
                        -Name "SPF: Soft Fail '~all' ($domainName)" `
                        -Status 'MEDIUM' `
                        -Detail "SPF uses '~all' (softfail) — unauthorised senders are marked but not rejected. Record: $spfText" `
                        -Recommendation "Upgrade to '-all' (hard fail) once all legitimate senders are in the SPF record." `
                        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-spf-configure' `
                        -CISControl 'CIS M365 6.1' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @($domainName)))
                }
                else {
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-001' `
                        -Category 'EmailSecurity' `
                        -Name "SPF: Configured with Hard Fail ($domainName)" `
                        -Status 'PASS' `
                        -Detail "SPF record found with hard fail (-all). Record: $spfText" `
                        -Recommendation 'Verify all legitimate sending sources are included. Review after adding new mail services.' `
                        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-spf-configure' `
                        -CISControl 'CIS M365 6.1' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @()))
                }
            }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'EML-001' `
                -Category 'EmailSecurity' `
                -Name "SPF: DNS Lookup Failed ($domainName)" `
                -Status 'INFO' `
                -Detail "Could not resolve TXT records for $domainName. Error: $_" `
                -Recommendation 'Verify DNS resolution. Resolve-DnsName requires Windows or PS 7 on Windows.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-spf-configure' `
                -CISControl 'CIS M365 6.1' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($domainName)))
        }

        # --- EML-002: DKIM (authoritative via Get-DkimSigningConfig) ---
        if ($dkimMap.ContainsKey($domainName)) {
            $dkimCfg = $dkimMap[$domainName]
            $results.Add((New-CheckResult `
                -CheckId 'EML-002' `
                -Category 'EmailSecurity' `
                -Name "DKIM: Signing Config ($domainName)" `
                -Status (if ($dkimCfg.Enabled) { 'PASS' } else { 'CRITICAL' }) `
                -Detail "DKIM signing — Enabled: $($dkimCfg.Enabled). Status: $($dkimCfg.Status). Selector1KeySize: $($dkimCfg.Selector1KeySize). Selector2KeySize: $($dkimCfg.Selector2KeySize)." `
                -Recommendation $(if (-not $dkimCfg.Enabled) {
                    'Enable DKIM in Exchange Admin Center: Security → Email authentication → DKIM. DKIM prevents message tampering in transit.'
                } else {
                    'DKIM is enabled. Rotate DKIM keys annually via Rotate-DkimSigningConfig.'
                }) `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dkim-configure' `
                -CISControl 'CIS M365 6.2' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects $(if (-not $dkimCfg.Enabled) { @($domainName) } else { @() })))
        }
        else {
            # DKIM config not found for this domain — DNS-based fallback
            $dkimFound = $false
            foreach ($selector in @('selector1', 'selector2')) {
                try {
                    $cname = Resolve-DnsName -Name "$selector._domainkey.$domainName" -Type CNAME -ErrorAction Stop
                    if ($cname) { $dkimFound = $true }
                }
                catch { }
            }

            $results.Add((New-CheckResult `
                -CheckId 'EML-002' `
                -Category 'EmailSecurity' `
                -Name "DKIM: $(if ($dkimFound) { 'Selectors Found (DNS)' } else { 'Not Configured' }) ($domainName)" `
                -Status (if ($dkimFound) { 'PASS' } elseif ($isDefault) { 'CRITICAL' } else { 'HIGH' }) `
                -Detail $(if ($dkimFound) {
                    "DKIM selector CNAME records found in DNS for $domainName. Domain not found in Get-DkimSigningConfig — this may be a subdomain or external domain."
                } else {
                    "No DKIM CNAME selector records found for $domainName and domain not in EXO DKIM config."
                }) `
                -Recommendation 'Enable DKIM in Exchange Admin Center. Publish the CNAME records shown in the portal before enabling.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dkim-configure' `
                -CISControl 'CIS M365 6.2' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects $(if (-not $dkimFound) { @($domainName) } else { @() })))
        }

        # --- EML-003 + EML-004: DMARC ---
        try {
            $dmarcDns    = Resolve-DnsName -Name "_dmarc.$domainName" -Type TXT -ErrorAction Stop
            $dmarcRecord = ($dmarcDns | Where-Object { $_.Strings -match 'v=DMARC1' } |
                           Select-Object -First 1).Strings -join ''

            if (-not $dmarcRecord) {
                $results.Add((New-CheckResult `
                    -CheckId 'EML-003' `
                    -Category 'EmailSecurity' `
                    -Name "DMARC: Record Missing ($domainName)" `
                    -Status (if ($isDefault) { 'CRITICAL' } else { 'HIGH' }) `
                    -Detail "No DMARC TXT record at _dmarc.$domainName." `
                    -Recommendation "Start in monitoring mode: v=DMARC1; p=none; rua=mailto:dmarc@$domainName. Then progress to quarantine → reject." `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                    -CISControl 'CIS M365 6.3' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @($domainName)))
            }
            else {
                $policy    = ([regex]::Match($dmarcRecord, '\bp=(\w+)')).Groups[1].Value.ToLower()
                $pctMatch  = [regex]::Match($dmarcRecord, '\bpct=(\d+)')
                $pctValue  = if ($pctMatch.Success) { [int]$pctMatch.Groups[1].Value } else { 100 }

                $dmarc003Status = switch ($policy) {
                    'reject'     { if ($pctValue -lt 100) { 'MEDIUM' } else { 'PASS' } }
                    'quarantine' { 'MEDIUM' }
                    default      { 'HIGH' }
                }

                $results.Add((New-CheckResult `
                    -CheckId 'EML-003' `
                    -Category 'EmailSecurity' `
                    -Name "DMARC: Policy p=$policy ($domainName)" `
                    -Status $dmarc003Status `
                    -Detail "DMARC record: $dmarcRecord. Policy: p=$policy. Enforcement: $pctValue%." `
                    -Recommendation $(switch ($policy) {
                        'reject'     { 'DMARC at reject. Ensure pct=100 and rua reporting is configured.' }
                        'quarantine' { "Upgrade from p=quarantine to p=reject once confident in SPF/DKIM alignment." }
                        default      { "Increase from p=none to p=quarantine then p=reject. Record: $dmarcRecord" }
                    }) `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                    -CISControl 'CIS M365 6.3' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $(if ($dmarc003Status -ne 'PASS') { @($domainName) } else { @() })))

                # EML-004: rua reporting
                $ruaMatch = [regex]::Match($dmarcRecord, '\brua=([^;]+)')
                $hasRua   = $ruaMatch.Success -and $ruaMatch.Groups[1].Value.Trim() -ne ''
                $results.Add((New-CheckResult `
                    -CheckId 'EML-004' `
                    -Category 'EmailSecurity' `
                    -Name "DMARC: Aggregate Reporting $(if ($hasRua) { 'Configured' } else { 'Missing' }) ($domainName)" `
                    -Status (if ($hasRua) { 'PASS' } else { 'LOW' }) `
                    -Detail $(if ($hasRua) {
                        "DMARC rua configured: $($ruaMatch.Groups[1].Value.Trim())"
                    } else {
                        "No rua= tag in DMARC record. No aggregate reports will be generated — blind to spoofing attempts."
                    }) `
                    -Recommendation $(if (-not $hasRua) {
                        "Add rua tag: v=DMARC1; p=$policy; rua=mailto:dmarc@$domainName. Consider a DMARC reporting service (Valimail, Dmarcian, etc.)."
                    } else {
                        'Review aggregate reports regularly to detect spoofing attempts.'
                    }) `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $(if (-not $hasRua) { @($domainName) } else { @() })))
            }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'EML-003' `
                -Category 'EmailSecurity' `
                -Name "DMARC: DNS Lookup Failed ($domainName)" `
                -Status (if ($isDefault) { 'CRITICAL' } else { 'HIGH' }) `
                -Detail "Could not resolve _dmarc.$domainName. Error: $_" `
                -Recommendation "Publish a DMARC record: v=DMARC1; p=none; rua=mailto:dmarc@$domainName" `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                -CISControl 'CIS M365 6.3' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($domainName)))
        }

        # --- EML-005: MX record ---
        try {
            $mxRecords = @(Resolve-DnsName -Name $domainName -Type MX -ErrorAction Stop |
                          Where-Object { $_.NameExchange })

            if ($mxRecords.Count -eq 0) {
                $results.Add((New-CheckResult `
                    -CheckId 'EML-005' `
                    -Category 'EmailSecurity' `
                    -Name "MX: No Records Found ($domainName)" `
                    -Status 'HIGH' `
                    -Detail "No MX records found for $domainName." `
                    -Recommendation 'Add MX record pointing to <tenant>.mail.protection.outlook.com (priority 0).' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/admin/get-help-with-domains/set-up-your-domain-host-specific-instructions' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @($domainName)))
            }
            else {
                $primaryMx    = $mxRecords | Sort-Object Preference | Select-Object -First 1
                $mxHost       = $primaryMx.NameExchange.TrimEnd('.')
                $pointsToEXO  = $mxHost -like '*.mail.protection.outlook.com'

                $results.Add((New-CheckResult `
                    -CheckId 'EML-005' `
                    -Category 'EmailSecurity' `
                    -Name "MX: $(if ($pointsToEXO) { 'Points to EXO' } else { 'Not Pointing to EXO' }) ($domainName)" `
                    -Status (if ($pointsToEXO) { 'PASS' } else { 'HIGH' }) `
                    -Detail "Primary MX: $mxHost (pref: $($primaryMx.Preference))." `
                    -Recommendation $(if (-not $pointsToEXO) {
                        'Primary MX should point to *.mail.protection.outlook.com to ensure Defender filtering is applied.'
                    } else {
                        'Verify no secondary MX bypasses EXO filtering.'
                    }) `
                    -Reference 'https://learn.microsoft.com/microsoft-365/admin/get-help-with-domains/set-up-your-domain-host-specific-instructions' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $(if (-not $pointsToEXO) { @($domainName) } else { @() })))
            }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'EML-005' `
                -Category 'EmailSecurity' `
                -Name "MX: DNS Lookup Failed ($domainName)" `
                -Status 'INFO' `
                -Detail "Could not resolve MX for $domainName. Error: $_" `
                -Recommendation 'Verify DNS resolution and retry.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/admin/get-help-with-domains/set-up-your-domain-host-specific-instructions' `
                -CISControl '' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($domainName)))
        }
    }

    # -------------------------------------------------------------------------
    # EML-006: Federation status (Get-AcceptedDomain.DomainType)
    # -------------------------------------------------------------------------
    $federatedDomains = @($domains | Where-Object { $_.DomainType -eq 'InternalRelay' -or $_.AuthenticationType -eq 'Federated' } |
                         ForEach-Object { $_.DomainName.ToString() })

    # Federated domains show as 'Managed' in Get-AcceptedDomain; federation type is in Entra.
    # We flag InternalRelay as noteworthy — full federation detail requires Graph.
    $internalRelay = @($domains | Where-Object { $_.DomainType -eq 'InternalRelay' } |
                      ForEach-Object { $_.DomainName.ToString() })

    $results.Add((New-CheckResult `
        -CheckId 'EML-006' `
        -Category 'EmailSecurity' `
        -Name 'Domain Type Overview' `
        -Status 'INFO' `
        -Detail "Accepted domains: $($domains.Count). InternalRelay (on-prem hybrid): $($internalRelay.Count) ($($internalRelay -join ', ')). For full federation detail (ADFS/Federated), use the Graph variant which queries /domains/federationConfiguration." `
        -Recommendation 'Review InternalRelay domains — they route mail to on-premises Exchange. For federation provider detail, run the Graph variant (Test-EmailAuth in scripts/modules/EmailSecurity/).' `
        -Reference 'https://learn.microsoft.com/exchange/mail-flow-best-practices/manage-accepted-domains/manage-accepted-domains' `
        -CISControl '' `
        -SC300Domain 'Email Security' `
        -LicenseRequired 'E3' `
        -AffectedObjects $internalRelay))

    return $results
}
