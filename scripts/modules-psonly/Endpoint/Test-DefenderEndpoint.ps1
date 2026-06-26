#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Security

<#
.SYNOPSIS
    Audits Defender for Endpoint coverage via Intune configuration profiles and Secure Score. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgDeviceManagementDeviceConfiguration -All,
    Get-MgSecuritySecureScore -Top 1, and Get-MgSecuritySecureScoreControlProfile -All
    instead of raw Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    Defender for Endpoint security posture settings are applied via Intune device
    configuration profiles. Microsoft.Graph.DeviceManagement provides native cmdlets
    to retrieve all profiles. Defender-specific MDE API endpoints (onboarding status,
    device health API) have no Get-Mg* equivalents and are marked as INFO stubs.

    Secure Score is used as a proxy for overall Defender coverage because MDE
    improvement actions are reflected in the score controls.

    NOTE on MDE-specific endpoints:
    Endpoints such as /security/microsoft.graph.security.runHuntingQuery and
    /deviceManagement/windowsDefenderApplicationControlSupplementalPolicies have no
    Get-Mg* equivalents in the current Microsoft.Graph.Security module. These emit
    INFO stubs with Az.Security / portal verification guidance.

    SEE ALSO (Graph variant):
        scripts/modules/Endpoint/Test-DefenderEndpoint.ps1

    Required connection:
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All","SecurityEvents.Read.All"

    Required scopes:
        DeviceManagementConfiguration.Read.All
        SecurityEvents.Read.All

    Required modules:
        Microsoft.Graph.DeviceManagement
        Microsoft.Graph.Security

    License: E5 / Defender for Endpoint Plan 2 for full coverage
    SC-300 Domain: Endpoint Security

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-DefenderEndpoint {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all device configuration profiles once
    # -------------------------------------------------------------------------
    $deviceConfigs = $null
    try {
        $deviceConfigs = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MDE-000' `
            -Category 'Endpoint' `
            -Name 'Defender Configuration Profile Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All".' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-endpoints-mdm' `
            -CISControl '' -SC300Domain 'Endpoint Security' -LicenseRequired 'E5' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # MDE-000: Defender for Endpoint onboarding status — INFO STUB
    # /security/microsoft.graph.security.runHuntingQuery has no Get-Mg* equivalent
    # -------------------------------------------------------------------------
    $mde000Detail  = 'Defender for Endpoint device onboarding status cannot be verified via the Microsoft.Graph.* PowerShell modules. '
    $mde000Detail += 'No Get-Mg* cmdlet covers the MDE device health or onboarding API. '
    $mde000Detail += 'Verification options: '
    $mde000Detail += '(1) Microsoft 365 Defender portal (security.microsoft.com) → Settings → Endpoints → Device inventory. '
    $mde000Detail += '(2) Graph variant: scripts/modules/Endpoint/Test-DefenderEndpoint.ps1 (uses Invoke-MgGraphRequest). '
    $mde000Detail += '(3) Install-Module Az.Security; Get-AzSecurityDevice for Azure-joined devices. '
    $mde000Detail += 'As a proxy, configuration profiles with Defender settings are checked below (MDE-001 through MDE-005).'

    $results.Add((New-CheckResult `
        -CheckId 'MDE-000' `
        -Category 'Endpoint' `
        -Name 'Defender for Endpoint Onboarding Coverage' `
        -Status 'INFO' `
        -Detail $mde000Detail `
        -Recommendation 'Verify MDE onboarding in the Defender portal. All Windows 10/11 Entra ID-joined devices should be onboarded. Use Intune endpoint security policies to onboard (Endpoint security → Endpoint detection & response).' `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-endpoints-mdm' `
        -CISControl '' -SC300Domain 'Endpoint Security' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-001: Real-time protection enabled (Defender Antivirus profiles)
    # Filter on windowsDefenderAdvancedThreatProtectionConfiguration or
    # windows10EndpointProtectionConfiguration
    # -------------------------------------------------------------------------
    $defenderProfiles = @($deviceConfigs | Where-Object {
        $_.AdditionalProperties['@odata.type'] -match 'windows10EndpointProtectionConfiguration|windows10GeneralConfiguration'
    })

    $antivirusProfiles = @($deviceConfigs | Where-Object {
        $_.AdditionalProperties['@odata.type'] -match 'windows10EndpointProtectionConfiguration'
    })

    if ($antivirusProfiles.Count -gt 0) {
        $rtpDisabled = @($antivirusProfiles | Where-Object {
            $_.AdditionalProperties['defenderScanDirection'] -eq $null -and
            $_.AdditionalProperties['defenderMonitorFileActivity'] -eq $null -and
            $_.AdditionalProperties['defenderRealtimeScanEnable'] -ne $true
        })

        # Also check for profiles explicitly disabling RTP
        $rtpExplicitlyOff = @($antivirusProfiles | Where-Object {
            $_.AdditionalProperties['defenderRealtimeScanEnable'] -eq $false
        })

        if ($rtpExplicitlyOff.Count -gt 0) {
            $mde001Status = 'CRITICAL'
            $mde001Detail = "Real-time protection is EXPLICITLY DISABLED in $($rtpExplicitlyOff.Count) profile(s): $($rtpExplicitlyOff | ForEach-Object { $_.DisplayName } | Join-String -Separator ', ')."
        }
        elseif ($rtpDisabled.Count -gt 0) {
            $mde001Status = 'MEDIUM'
            $mde001Detail = "$($antivirusProfiles.Count) endpoint protection profile(s) found but $($rtpDisabled.Count) do not explicitly enable real-time protection (defenderRealtimeScanEnable not set to true). Windows Defender is on by default but explicit enforcement is recommended."
        }
        else {
            $mde001Status = 'PASS'
            $mde001Detail = "Real-time protection is explicitly enabled in $($antivirusProfiles.Count) Windows 10/11 endpoint protection profile(s)."
        }
    }
    else {
        $mde001Status = 'HIGH'
        $mde001Detail = 'No Windows 10/11 endpoint protection configuration profiles found. Real-time protection is not being managed via Intune. Devices rely on Windows Defender default settings only.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-001' `
        -Category 'Endpoint' `
        -Name 'Defender — Real-Time Protection Enabled' `
        -Status $mde001Status `
        -Detail $mde001Detail `
        -Recommendation "Create an Intune device configuration profile for Windows 10/11 and set 'Defender > Real-time monitoring' to 'Yes'. This explicitly enforces real-time protection through policy." `
        -Reference 'https://learn.microsoft.com/mem/intune/configuration/device-restrictions-windows-10' `
        -CISControl 'CIS 10.1' -SC300Domain 'Endpoint Security' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-002: Cloud-delivered protection (MAPS / cloud protection level)
    # -------------------------------------------------------------------------
    if ($antivirusProfiles.Count -gt 0) {
        $cloudProtDisabled = @($antivirusProfiles | Where-Object {
            $_.AdditionalProperties['defenderCloudBlockLevel'] -eq $null -or
            $_.AdditionalProperties['defenderCloudBlockLevel'] -eq 'notConfigured'
        })

        if ($cloudProtDisabled.Count -gt 0) {
            $mde002Status = 'MEDIUM'
            $mde002Detail = "$($antivirusProfiles.Count) endpoint protection profile(s) checked. $($cloudProtDisabled.Count) do not configure cloud protection level (defenderCloudBlockLevel). Cloud-delivered protection enhances detection of new threats."
        }
        else {
            $mde002Status = 'PASS'
            $mde002Detail = "Cloud protection block level is configured in all $($antivirusProfiles.Count) endpoint protection profile(s)."
        }
    }
    else {
        $mde002Status = 'HIGH'
        $mde002Detail = 'No Windows endpoint protection profiles found. Cloud-delivered protection level cannot be assessed.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-002' `
        -Category 'Endpoint' `
        -Name 'Defender — Cloud-Delivered Protection' `
        -Status $mde002Status `
        -Detail $mde002Detail `
        -Recommendation "Set Defender cloud protection level to 'High' or 'High Plus' in Intune endpoint protection profiles. Cloud protection provides near real-time detection of new malware strains." `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-cloud-block-timeout-period-microsoft-defender-antivirus' `
        -CISControl 'CIS 10.1' -SC300Domain 'Endpoint Security' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-003: Tamper protection — INFO STUB
    # Tamper protection config is not exposed in Get-Mg* properties
    # -------------------------------------------------------------------------
    $mde003Detail  = 'Tamper protection cannot be verified via Microsoft.Graph.DeviceManagement cmdlets. '
    $mde003Detail += 'It is configured as a separate Intune endpoint security policy (Endpoint security > Antivirus > Windows Defender Antivirus). '
    $mde003Detail += 'Verification steps: (1) Intune portal → Endpoint security → Antivirus → Review policies. '
    $mde003Detail += "(2) Verify 'Tamper Protection' is set to 'Enabled' in Windows Security Center configuration. "
    $mde003Detail += '(3) In the Defender portal: Settings → Endpoints → Advanced features → Tamper protection.'

    $results.Add((New-CheckResult `
        -CheckId 'MDE-003' `
        -Category 'Endpoint' `
        -Name 'Defender — Tamper Protection Enabled' `
        -Status 'INFO' `
        -Detail $mde003Detail `
        -Recommendation "Enable Tamper Protection via Intune (Endpoint security > Antivirus). Tamper protection prevents local processes or users from disabling Defender components, even with local admin rights." `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection' `
        -CISControl '' -SC300Domain 'Endpoint Security' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-004: Attack Surface Reduction (ASR) rules
    # Check for windows10EndpointProtectionConfiguration with ASR settings
    # -------------------------------------------------------------------------
    if ($antivirusProfiles.Count -gt 0) {
        $asrProfiles = @($antivirusProfiles | Where-Object {
            $_.AdditionalProperties.Keys -match 'attackSurface|asrRule|asr'
        })

        # Alternative: check for at least one ASR-specific key
        $asrAny = @($antivirusProfiles | Where-Object {
            ($_.AdditionalProperties.Keys | Where-Object { $_ -match 'defender.*rule|attackSurface' }).Count -gt 0
        })

        if ($asrAny.Count -gt 0) {
            $mde004Status = 'PASS'
            $mde004Detail = "Attack Surface Reduction rules appear configured in $($asrAny.Count) endpoint protection profile(s). Verify rule modes (block vs. audit) in the Defender portal."
        }
        else {
            # Check Endpoint security policies (different type)
            $mde004Status = 'HIGH'
            $mde004Detail = 'No ASR rule configuration detected in Windows endpoint protection profiles. ASR rules are a key Defender for Endpoint control. Check Intune Endpoint security > Attack surface reduction policies separately.'
        }
    }
    else {
        $mde004Status = 'HIGH'
        $mde004Detail = 'No Windows endpoint protection profiles found. ASR rules cannot be assessed. Configure ASR via Intune Endpoint security > Attack surface reduction.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-004' `
        -Category 'Endpoint' `
        -Name 'Defender — Attack Surface Reduction Rules' `
        -Status $mde004Status `
        -Detail $mde004Detail `
        -Recommendation "Enable ASR rules in block mode via Intune (Endpoint security → Attack surface reduction). Start with audit mode for 30 days to avoid disruption, then convert to block. Priority rules: block Office process injection, credential stealing from LSASS, ransomware." `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference' `
        -CISControl 'CIS 10.5' -SC300Domain 'Endpoint Security' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-005: Firewall policies
    # Check for Windows Firewall configuration in Intune profiles
    # -------------------------------------------------------------------------
    $firewallProfiles = @($deviceConfigs | Where-Object {
        $_.AdditionalProperties['@odata.type'] -match 'windows10EndpointProtectionConfiguration' -and
        $_.AdditionalProperties.Keys -match 'firewall'
    })

    if ($firewallProfiles.Count -gt 0) {
        $firewallDisabled = @($firewallProfiles | Where-Object {
            $_.AdditionalProperties['firewallEnabled'] -eq $false
        })

        if ($firewallDisabled.Count -gt 0) {
            $mde005Status = 'CRITICAL'
            $mde005Detail = "Windows Firewall is EXPLICITLY DISABLED in $($firewallDisabled.Count) profile(s): $($firewallDisabled | ForEach-Object { $_.DisplayName } | Join-String -Separator ', ')."
        }
        else {
            $mde005Status = 'PASS'
            $mde005Detail = "Windows Firewall configuration profiles found ($($firewallProfiles.Count)). Firewall is not explicitly disabled."
        }
    }
    else {
        $mde005Status = 'MEDIUM'
        $mde005Detail = 'No Windows Firewall-specific configuration detected in Intune endpoint protection profiles. Windows Firewall is enabled by default but is not being explicitly managed via policy.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-005' `
        -Category 'Endpoint' `
        -Name 'Defender — Windows Firewall Managed by Policy' `
        -Status $mde005Status `
        -Detail $mde005Detail `
        -Recommendation 'Manage Windows Firewall via Intune endpoint protection or Endpoint security > Firewall policy. Ensure domain, private, and public profiles are all set to enabled with appropriate inbound blocking rules.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/endpoint-security-firewall-policy' `
        -CISControl 'CIS 12.1' -SC300Domain 'Endpoint Security' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-006: Secure Score — MDE-related controls
    # Uses Get-MgSecuritySecureScoreControlProfile to find MDE-specific controls
    # -------------------------------------------------------------------------
    try {
        $scoreControls = Get-MgSecuritySecureScoreControlProfile -All -ErrorAction Stop

        $mdeControls = @($scoreControls | Where-Object {
            $_.ControlCategory -match 'Endpoint|Device' -or
            $_.Title -match 'Defender|MDE|endpoint|antivirus|BitLocker'
        })

        $mdeUnaddressed = @($mdeControls | Where-Object {
            -not $_.ControlStateUpdates -or $_.ControlStateUpdates.Count -eq 0
        })

        $topMdeUnaddressed = $mdeUnaddressed |
            Sort-Object MaxScore -Descending |
            Select-Object -First 5 |
            ForEach-Object { "$($_.Title) (+$($_.MaxScore) pts)" }

        $mde006Status = if ($mdeUnaddressed.Count -gt 10) { 'HIGH' }
                        elseif ($mdeUnaddressed.Count -gt 5) { 'MEDIUM' }
                        else { 'PASS' }

        $mde006Detail = "Secure Score endpoint/device controls: $($mdeControls.Count) total, $($mdeUnaddressed.Count) unaddressed. Top unaddressed: $($topMdeUnaddressed -join '; ')."

        $results.Add((New-CheckResult `
            -CheckId 'MDE-006' `
            -Category 'Endpoint' `
            -Name 'Defender — Secure Score Endpoint Controls' `
            -Status $mde006Status `
            -Detail $mde006Detail `
            -Recommendation 'Use Microsoft Secure Score endpoint improvement actions to identify remaining MDE gaps. Actions include enabling EDR in block mode, configuring advanced threat protection features, and ensuring scan coverage.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score' `
            -CISControl '' -SC300Domain 'Endpoint Security' -LicenseRequired 'E5' `
            -AffectedObjects @($topMdeUnaddressed)))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MDE-006' `
            -Category 'Endpoint' `
            -Name 'Defender — Secure Score Endpoint Controls' `
            -Status 'INFO' `
            -Detail "Secure Score endpoint controls check skipped: API error. Required: SecurityEvents.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "SecurityEvents.Read.All".' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender/microsoft-secure-score' `
            -CISControl '' -SC300Domain 'Endpoint Security' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    return $results
}
