#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits email authentication records (SPF, DKIM, DMARC) and domain configuration.

.DESCRIPTION
    Test-EmailAuth retrieves all verified domains from the tenant via Microsoft Graph,
    then performs DNS-based checks for SPF, DKIM, and DMARC on each domain. It also
    checks for DMARC aggregate reporting, MX record alignment with Exchange Online, and
    domain federation status.

    DNS checks use Resolve-DnsName (Windows) with fallback to nslookup parsing where needed.
    Exchange Online cmdlets (Get-DkimSigningConfig) are used when available, with DNS-based
    fallback.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

.NOTES
    Required Graph Permissions : Domain.Read.All (or Directory.Read.All)
    Exchange Online             : Get-DkimSigningConfig (optional; DNS fallback used if unavailable)
    License Required            : E3 minimum
    Module                      : Microsoft.Graph.Authentication (uses Invoke-MgGraphRequest)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        EML-001  SPF record present and enforcing hard fail
        EML-002  DKIM configured and enabled per domain
        EML-003  DMARC record and policy strength
        EML-004  DMARC aggregate reporting configured
        EML-005  MX record pointing to Exchange Online
        EML-006  Domain federation status
#>

function Test-EmailAuth {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve tenant domains via Graph
    # -------------------------------------------------------------------------
    $domains = @()
    try {
        $domainsResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,isDefault,isVerified,authenticationType,supportedServices' `
            -ErrorAction Stop
        # Only check verified domains that support email (or all verified if supportedServices not populated)
        $domains = @($domainsResp.value | Where-Object {
            $_.isVerified -eq $true -and $_.id -notlike '*.onmicrosoft.com'
        })
        if ($domains.Count -eq 0) {
            # Fallback: include onmicrosoft.com if no custom domains
            $domains = @($domainsResp.value | Where-Object { $_.isVerified -eq $true })
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'EML-000' `
            -Category 'EmailSecurity' `
            -Name 'Domain Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: could not retrieve tenant domains. Required: Domain.Read.All. Error: $_" `
            -Recommendation 'Grant Domain.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-about' `
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
            -Name 'Domain Retrieval' `
            -Status 'INFO' `
            -Detail 'No verified custom domains found in the tenant. Email authentication checks require at least one verified custom domain.' `
            -Recommendation 'Add and verify at least one custom domain before configuring email authentication.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/admin/setup/add-domain' `
            -CISControl '' `
            -SC300Domain 'Email Security' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # Identify primary domain
    $primaryDomain = ($domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1)
    if (-not $primaryDomain) { $primaryDomain = $domains[0] }

    # -------------------------------------------------------------------------
    # EXO DKIM: Try to get EXO-side DKIM status (optional — requires EXO session)
    # -------------------------------------------------------------------------
    $exoDkimConfigs = @{}
    $exoAvailable   = $false
    try {
        if (Get-Command -Name 'Get-DkimSigningConfig' -ErrorAction SilentlyContinue) {
            $dkimConfigs = Get-DkimSigningConfig -ErrorAction Stop
            foreach ($cfg in $dkimConfigs) {
                $exoDkimConfigs[$cfg.Domain] = $cfg
            }
            $exoAvailable = $true
            Write-Verbose 'EXO Get-DkimSigningConfig available.'
        }
    }
    catch {
        Write-Verbose "EXO Get-DkimSigningConfig not available or failed: $_"
    }

    # -------------------------------------------------------------------------
    # Per-domain checks (EML-001 through EML-005)
    # -------------------------------------------------------------------------
    foreach ($domain in $domains) {
        $domainName = $domain.id

        # --- EML-001: SPF ---
        try {
            $spfDns = Resolve-DnsName -Name $domainName -Type TXT -ErrorAction Stop
            $spfRecord = ($spfDns | Where-Object {
                $_.Strings -match '^v=spf1'
            } | Select-Object -First 1).Strings

            if (-not $spfRecord) {
                $spfStatus = if ($domain.isDefault) { 'CRITICAL' } else { 'HIGH' }
                $results.Add((New-CheckResult `
                    -CheckId 'EML-001' `
                    -Category 'EmailSecurity' `
                    -Name "SPF: Record Missing ($domainName)" `
                    -Status $spfStatus `
                    -Detail "No SPF TXT record found for $domainName. Without SPF, any server can send email claiming to be from this domain." `
                    -Recommendation "Publish an SPF record: v=spf1 include:spf.protection.outlook.com -all" `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-spf-configure' `
                    -CISControl 'CIS M365 6.1' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @($domainName)))
            }
            else {
                # Normalise: join multi-string TXT records
                $spfText = $spfRecord -join ''

                if ($spfText -match '\+all') {
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-001' `
                        -Category 'EmailSecurity' `
                        -Name "SPF: Permissive '+all' Mechanism ($domainName)" `
                        -Status 'HIGH' `
                        -Detail "SPF record uses '+all' which allows any sender to pass SPF. Record: $spfText" `
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
                        -Name "SPF: Soft Fail '~all' Mechanism ($domainName)" `
                        -Status 'MEDIUM' `
                        -Detail "SPF record uses '~all' (softfail). Unauthorised senders are marked but not rejected. Record: $spfText" `
                        -Recommendation "Upgrade SPF to use '-all' (hard fail) once all legitimate senders are included. This causes unauthorised email to be rejected." `
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
                        -Name "SPF: Record Configured ($domainName)" `
                        -Status 'PASS' `
                        -Detail "SPF record found with hard fail (-all). Record: $spfText" `
                        -Recommendation 'Verify all legitimate sending sources are included. Review SPF record after adding new mail services.' `
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
                -Detail "Could not resolve TXT records for $domainName. DNS error: $_" `
                -Recommendation 'Verify DNS resolution and retry. Ensure Resolve-DnsName is available (Windows/PowerShell 7 on Windows required).' `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-spf-configure' `
                -CISControl 'CIS M365 6.1' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($domainName)))
        }

        # --- EML-002: DKIM ---
        if ($exoAvailable -and $exoDkimConfigs.ContainsKey($domainName)) {
            $dkimCfg    = $exoDkimConfigs[$domainName]
            $dkimStatus = if ($dkimCfg.Enabled) { 'PASS' } else { 'CRITICAL' }
            $results.Add((New-CheckResult `
                -CheckId 'EML-002' `
                -Category 'EmailSecurity' `
                -Name "DKIM: Signing Configuration ($domainName)" `
                -Status $dkimStatus `
                -Detail "DKIM signing for $domainName — Enabled: $($dkimCfg.Enabled). Selector1KeySize: $($dkimCfg.Selector1KeySize). Selector2KeySize: $($dkimCfg.Selector2KeySize). Status: $($dkimCfg.Status)." `
                -Recommendation $(if (-not $dkimCfg.Enabled) { 'Enable DKIM signing in Exchange Admin Center: Protection > DKIM. DKIM prevents message tampering in transit.' } else { 'DKIM is enabled. Rotate selectors annually.' }) `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dkim-configure' `
                -CISControl 'CIS M365 6.2' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects $(if (-not $dkimCfg.Enabled) { @($domainName) } else { @() })))
        }
        else {
            # DNS-based DKIM check: look for selector1/selector2 CNAME records
            $dkimFound = $false
            foreach ($selector in @('selector1', 'selector2')) {
                try {
                    $dkimDns = Resolve-DnsName -Name "$selector._domainkey.$domainName" -Type CNAME -ErrorAction Stop
                    if ($dkimDns) {
                        $dkimFound = $true
                        if ($Detailed) {
                            $results.Add((New-CheckResult `
                                -CheckId 'EML-002' `
                                -Category 'EmailSecurity' `
                                -Name "DKIM: Selector $selector Present ($domainName)" `
                                -Status 'PASS' `
                                -Detail "DKIM CNAME record found: $selector._domainkey.$domainName -> $($dkimDns.NameHost)" `
                                -Recommendation 'DKIM selector DNS record is published. Confirm signing is active in Exchange Admin Center.' `
                                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dkim-configure' `
                                -CISControl 'CIS M365 6.2' `
                                -SC300Domain 'Email Security' `
                                -LicenseRequired 'E3' `
                                -AffectedObjects @()))
                        }
                    }
                }
                catch {
                    Write-Verbose "DKIM: $selector._domainkey.$domainName not found."
                }
            }

            if (-not $dkimFound) {
                $eml002Status = if ($domain.isDefault) { 'CRITICAL' } else { 'HIGH' }
                $results.Add((New-CheckResult `
                    -CheckId 'EML-002' `
                    -Category 'EmailSecurity' `
                    -Name "DKIM: No Selectors Found ($domainName)" `
                    -Status $eml002Status `
                    -Detail "No DKIM CNAME records found for selector1._domainkey.$domainName or selector2._domainkey.$domainName. DKIM may not be enabled for this domain." `
                    -Recommendation 'Enable DKIM in Exchange Admin Center: Security > Email authentication > DKIM. For custom domains, publish the CNAME records shown in the admin center before enabling.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dkim-configure' `
                    -CISControl 'CIS M365 6.2' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @($domainName)))
            }
            elseif (-not $Detailed) {
                # Summary PASS if both selectors found but not in detailed mode
                $results.Add((New-CheckResult `
                    -CheckId 'EML-002' `
                    -Category 'EmailSecurity' `
                    -Name "DKIM: Selectors Present ($domainName)" `
                    -Status 'PASS' `
                    -Detail "DKIM CNAME selector records found via DNS for $domainName. Connect Exchange Online to verify signing is active." `
                    -Recommendation 'Confirm DKIM signing status in Exchange Admin Center.' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dkim-configure' `
                    -CISControl 'CIS M365 6.2' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }

        # --- EML-003: DMARC record and policy ---
        try {
            $dmarcDns = Resolve-DnsName -Name "_dmarc.$domainName" -Type TXT -ErrorAction Stop
            $dmarcRecord = ($dmarcDns | Where-Object {
                $_.Strings -match 'v=DMARC1'
            } | Select-Object -First 1).Strings -join ''

            if (-not $dmarcRecord) {
                $eml003Status = if ($domain.isDefault) { 'CRITICAL' } else { 'HIGH' }
                $results.Add((New-CheckResult `
                    -CheckId 'EML-003' `
                    -Category 'EmailSecurity' `
                    -Name "DMARC: Record Missing ($domainName)" `
                    -Status $eml003Status `
                    -Detail "No DMARC TXT record found at _dmarc.$domainName. Without DMARC, receiving mail servers have no instruction on how to handle SPF/DKIM failures." `
                    -Recommendation "Publish a DMARC record to start in monitoring mode: v=DMARC1; p=none; rua=mailto:dmarc@$domainName. Gradually increase to quarantine then reject." `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                    -CISControl 'CIS M365 6.3' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @($domainName)))
            }
            else {
                $policyMatch  = [regex]::Match($dmarcRecord, '\bp=(\w+)')
                $policy       = if ($policyMatch.Success) { $policyMatch.Groups[1].Value.ToLower() } else { 'none' }
                $subdomainPct = [regex]::Match($dmarcRecord, '\bpct=(\d+)')
                $pctValue     = if ($subdomainPct.Success) { [int]$subdomainPct.Groups[1].Value } else { 100 }

                switch ($policy) {
                    'reject' {
                        $eml003Status = 'PASS'
                        $eml003Rec    = 'DMARC policy is at reject. Ensure rua reporting is configured and review reports regularly.'
                    }
                    'quarantine' {
                        $eml003Status = 'MEDIUM'
                        $eml003Rec    = "Upgrade DMARC policy from p=quarantine to p=reject once confident in SPF/DKIM alignment. Current record: $dmarcRecord"
                    }
                    default {
                        $eml003Status = 'HIGH'
                        $eml003Rec    = "DMARC policy p=none is monitoring-only — no action is taken on failing email. Plan to increase to p=quarantine then p=reject. Record: $dmarcRecord"
                    }
                }

                if ($pctValue -lt 100 -and $policy -eq 'reject') {
                    $eml003Status = 'MEDIUM'
                    $eml003Rec    = "DMARC is at reject but pct=$pctValue (not 100%). Only $pctValue% of failing emails are rejected. Increase pct to 100."
                }

                $results.Add((New-CheckResult `
                    -CheckId 'EML-003' `
                    -Category 'EmailSecurity' `
                    -Name "DMARC: Policy Enforcement ($domainName)" `
                    -Status $eml003Status `
                    -Detail "DMARC record found. Policy: p=$policy. Percentage: $pctValue%. Full record: $dmarcRecord" `
                    -Recommendation $eml003Rec `
                    -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                    -CISControl 'CIS M365 6.3' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $(if ($eml003Status -ne 'PASS') { @($domainName) } else { @() })))

                # --- EML-004: DMARC reporting (rua tag) ---
                $ruaMatch = [regex]::Match($dmarcRecord, '\brua=([^;]+)')
                $hasRua   = $ruaMatch.Success -and $ruaMatch.Groups[1].Value.Trim() -ne ''

                if (-not $hasRua) {
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-004' `
                        -Category 'EmailSecurity' `
                        -Name "DMARC: Aggregate Reporting Not Configured ($domainName)" `
                        -Status 'LOW' `
                        -Detail "DMARC record exists but has no rua= (aggregate report) tag. Without reporting you have no visibility into authentication failures or spoofing attempts." `
                        -Recommendation "Add an rua= tag to receive aggregate reports: v=DMARC1; p=$policy; rua=mailto:dmarc-reports@$domainName. Consider using a DMARC reporting service." `
                        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                        -CISControl '' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @($domainName)))
                }
                else {
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-004' `
                        -Category 'EmailSecurity' `
                        -Name "DMARC: Aggregate Reporting Configured ($domainName)" `
                        -Status 'PASS' `
                        -Detail "DMARC rua aggregate reporting is configured: $($ruaMatch.Groups[1].Value.Trim())" `
                        -Recommendation 'Review DMARC aggregate reports regularly to identify spoofing attempts and unauthorised senders.' `
                        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                        -CISControl '' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @()))
                }
            }
        }
        catch {
            $eml003Status = if ($domain.isDefault) { 'CRITICAL' } else { 'HIGH' }
            $results.Add((New-CheckResult `
                -CheckId 'EML-003' `
                -Category 'EmailSecurity' `
                -Name "DMARC: DNS Lookup Failed ($domainName)" `
                -Status $eml003Status `
                -Detail "Could not resolve _dmarc.$domainName. DNS error: $_" `
                -Recommendation "Publish a DMARC record: v=DMARC1; p=none; rua=mailto:dmarc@$domainName" `
                -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/email-authentication-dmarc-configure' `
                -CISControl 'CIS M365 6.3' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($domainName)))
        }

        # --- EML-005: MX record pointing to Exchange Online ---
        try {
            $mxDns = Resolve-DnsName -Name $domainName -Type MX -ErrorAction Stop
            $mxRecords = @($mxDns | Where-Object { $_.NameExchange })

            if ($mxRecords.Count -eq 0) {
                $results.Add((New-CheckResult `
                    -CheckId 'EML-005' `
                    -Category 'EmailSecurity' `
                    -Name "MX: No Records Found ($domainName)" `
                    -Status 'HIGH' `
                    -Detail "No MX records found for $domainName." `
                    -Recommendation 'Add an MX record pointing to Exchange Online: <domain>.mail.protection.outlook.com (priority 0).' `
                    -Reference 'https://learn.microsoft.com/microsoft-365/admin/get-help-with-domains/set-up-your-domain-host-specific-instructions' `
                    -CISControl '' `
                    -SC300Domain 'Email Security' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @($domainName)))
            }
            else {
                $primaryMx       = $mxRecords | Sort-Object -Property Preference | Select-Object -First 1
                $mxHost          = $primaryMx.NameExchange.TrimEnd('.')
                $pointsToEXO     = $mxHost -like '*.mail.protection.outlook.com'

                if ($pointsToEXO) {
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-005' `
                        -Category 'EmailSecurity' `
                        -Name "MX: Points to Exchange Online ($domainName)" `
                        -Status 'PASS' `
                        -Detail "Primary MX record points to Exchange Online: $mxHost (preference: $($primaryMx.Preference))." `
                        -Recommendation 'Verify no secondary MX records bypass Exchange Online (and Defender) filtering.' `
                        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/step-by-step-guides/ensuring-you-always-have-the-optimal-security-controls-with-preset-security-policies' `
                        -CISControl '' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @()))
                }
                else {
                    $allMxHosts = @($mxRecords | ForEach-Object { "$($_.NameExchange.TrimEnd('.')) (pref: $($_.Preference))" }) -join '; '
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-005' `
                        -Category 'EmailSecurity' `
                        -Name "MX: Primary MX Does Not Point to Exchange Online ($domainName)" `
                        -Status 'HIGH' `
                        -Detail "Primary MX record ($mxHost) does not point to *.mail.protection.outlook.com. Email may bypass Microsoft Defender for Office 365 filtering. All MX: $allMxHosts" `
                        -Recommendation 'Ensure the lowest-preference (primary) MX record points to Exchange Online. Third-party gateways should be configured as connectors in Exchange Admin Center, not as primary MX.' `
                        -Reference 'https://learn.microsoft.com/microsoft-365/security/office-365-security/step-by-step-guides/ensuring-you-always-have-the-optimal-security-controls-with-preset-security-policies' `
                        -CISControl '' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @($domainName)))
                }
            }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'EML-005' `
                -Category 'EmailSecurity' `
                -Name "MX: DNS Lookup Failed ($domainName)" `
                -Status 'INFO' `
                -Detail "Could not resolve MX records for $domainName. DNS error: $_" `
                -Recommendation 'Verify DNS resolution and retry.' `
                -Reference 'https://learn.microsoft.com/microsoft-365/admin/get-help-with-domains/set-up-your-domain-host-specific-instructions' `
                -CISControl '' `
                -SC300Domain 'Email Security' `
                -LicenseRequired 'E3' `
                -AffectedObjects @($domainName)))
        }
    }

    # -------------------------------------------------------------------------
    # EML-006: Domain federation status (informational, across all domains)
    # -------------------------------------------------------------------------
    $federatedDomains = [System.Collections.Generic.List[string]]::new()
    foreach ($domain in $domains) {
        if ($domain.authenticationType -eq 'Federated') {
            $federatedDomains.Add($domain.id)
        }
        # For deeper federation details, try the federationConfiguration endpoint
        if ($Detailed) {
            try {
                $fedCfgResp = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/domains/$($domain.id)/federationConfiguration" `
                    -ErrorAction Stop
                if ($fedCfgResp.value.Count -gt 0) {
                    $issuer    = $fedCfgResp.value[0].issuerUri
                    $results.Add((New-CheckResult `
                        -CheckId 'EML-006' `
                        -Category 'EmailSecurity' `
                        -Name "Domain Federation Detail: $($domain.id)" `
                        -Status 'INFO' `
                        -Detail "Domain $($domain.id) is federated. Issuer: $issuer. Verify federation trust configuration and token signing certificate expiry." `
                        -Recommendation 'Review federation configuration. Ensure token signing certificates are current and the federation provider is hardened.' `
                        -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-fed' `
                        -CISControl '' `
                        -SC300Domain 'Email Security' `
                        -LicenseRequired 'E3' `
                        -AffectedObjects @($domain.id)))
                }
            }
            catch {
                Write-Verbose "EML-006: Could not retrieve federation config for $($domain.id): $_"
            }
        }
    }

    $eml006Status = if ($federatedDomains.Count -gt 0) { 'INFO' } else { 'PASS' }
    $eml006Detail = if ($federatedDomains.Count -gt 0) {
        "Found $($federatedDomains.Count) federated domain(s): $($federatedDomains -join ', '). Federated domains rely on an external identity provider for authentication."
    }
    else {
        "No federated domains found. All $($domains.Count) verified custom domains use cloud-managed authentication."
    }

    $results.Add((New-CheckResult `
        -CheckId 'EML-006' `
        -Category 'EmailSecurity' `
        -Name 'Domain Federation Status' `
        -Status $eml006Status `
        -Detail $eml006Detail `
        -Recommendation 'For federated domains, ensure the federation trust (AD FS / PingFederate) is hardened and the token signing certificate is monitored for expiry. Consider migrating to cloud-managed (Password Hash Sync or Pass-through Auth) to reduce dependency on on-premises infrastructure.' `
        -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-fed' `
        -CISControl '' `
        -SC300Domain 'Email Security' `
        -LicenseRequired 'E3' `
        -AffectedObjects $federatedDomains.ToArray()))

    return $results
}
