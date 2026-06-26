#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Microsoft Defender for Endpoint configuration and Intune Defender policies.

.DESCRIPTION
    Test-DefenderEndpoint evaluates MDE onboarding status, Defender AV configuration
    (real-time protection, cloud protection, tamper protection), Attack Surface Reduction
    rules, and firewall policy enforcement via Intune device configuration profiles.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        DeviceManagementConfiguration.Read.All
        WindowsDefenderATP (via Graph Security API — MDE-001 only)

    License Required:
        MDE-001, MDE-005: E5 (Defender for Endpoint P2)
        MDE-002 through MDE-006: E3 (Intune)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/Endpoint/Test-DefenderEndpoint.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-DefenderEndpoint {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all device configuration profiles (used by multiple checks)
    # -------------------------------------------------------------------------
    $deviceConfigs = $null
    try {
        $uri = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$top=100&$select=id,displayName,@odata.type'
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $deviceConfigs = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $response.value) { $deviceConfigs.Add($item) }
        $nextLink = $response.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($item in $page.value) { $deviceConfigs.Add($item) }
            $nextLink = $page.'@odata.nextLink'
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MDE-000' `
            -Category 'Endpoint' `
            -Name 'Defender Configuration Profile Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementConfiguration.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/advanced-threat-protection' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # MDE-001: Defender for Endpoint onboarding status
    # -------------------------------------------------------------------------
    try {
        $managedDevUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,managedDeviceOwnerType&`$top=1"
        $mdResponse = Invoke-MgGraphRequest -Method GET -Uri $managedDevUri -ErrorAction Stop
        $winDevCountUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/`$count"
        try {
            $winHeaders = @{'ConsistencyLevel' = 'eventual'; 'Filter' = "operatingSystem eq 'Windows'"}
            $totalWinDevices = [int](Invoke-MgGraphRequest -Method GET -Uri $winDevCountUri `
                -Headers @{'ConsistencyLevel' = 'eventual'} -ErrorAction Stop)
        }
        catch {
            $totalWinDevices = $null
        }

        # Check if MDE connector is configured via device configurations
        $mdeConnectorProfile = @($deviceConfigs | Where-Object {
            $_.'@odata.type' -match 'windowsDefenderAdvancedThreatProtection' -or
            $_.displayName -match 'MDE|Defender for Endpoint|ATP'
        })

        if ($mdeConnectorProfile.Count -gt 0) {
            $mde001Status = 'INFO'
            $mde001Detail = "MDE onboarding profile found: $($mdeConnectorProfile | ForEach-Object { $_.displayName } | Join-String -Separator ', ')."
            if ($totalWinDevices) { $mde001Detail += " Total Windows devices enrolled: $totalWinDevices." }
        }
        else {
            $mde001Status = 'HIGH'
            $mde001Detail = 'No Defender for Endpoint onboarding profile found in Intune device configurations.'
            if ($totalWinDevices) { $mde001Detail += " $totalWinDevices Windows devices enrolled but may not be MDE-onboarded." }
        }

        $results.Add((New-CheckResult `
            -CheckId 'MDE-001' `
            -Category 'Endpoint' `
            -Name 'Defender for Endpoint Onboarding' `
            -Status $mde001Status `
            -Detail $mde001Detail `
            -Recommendation 'Deploy the MDE onboarding profile via Intune to all Windows devices. Verify onboarding status in the Microsoft 365 Defender portal.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-endpoints-mdm' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'MDE-001' `
            -Category 'Endpoint' `
            -Name 'Defender for Endpoint Onboarding' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: DeviceManagementManagedDevices.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementManagedDevices.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/configure-endpoints-mdm' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # MDE-002: Real-time protection enforced via Intune (Windows Defender AV profile)
    # -------------------------------------------------------------------------
    $windowsDefenderProfiles = @($deviceConfigs | Where-Object {
        $_.'@odata.type' -match 'windows10EndpointProtection' -or
        $_.'@odata.type' -match 'windows10GeneralConfiguration' -or
        $_.displayName -match 'Defender|Antivirus|AV|Endpoint Protection'
    })

    $rtpEnforced = $false
    foreach ($profile in $windowsDefenderProfiles) {
        try {
            $profileDetail = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($profile.id)" `
                -ErrorAction Stop
            if ($profileDetail.defenderRealTimeScanDirection -ne $null -or
                $profileDetail.defenderMonitorFileActivity -ne $null -or
                $profileDetail.realTimeMonitoringEnabled -eq $true) {
                $rtpEnforced = $true
                break
            }
        }
        catch {
            Write-Verbose "Could not fetch profile detail for $($profile.displayName): $_"
        }
    }

    if ($windowsDefenderProfiles.Count -eq 0) {
        $mde002Status = 'HIGH'
        $mde002Detail = 'No Windows Defender / Endpoint Protection configuration profiles found in Intune.'
    }
    elseif (-not $rtpEnforced) {
        $mde002Status = 'HIGH'
        $mde002Detail = "Found $($windowsDefenderProfiles.Count) Defender-related profile(s) but real-time protection setting not explicitly enforced. Profiles: $($windowsDefenderProfiles | ForEach-Object { $_.displayName } | Join-String -Separator ', ')."
    }
    else {
        $mde002Status = 'PASS'
        $mde002Detail = "Real-time protection is enforced via Intune Defender configuration profile."
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-002' `
        -Category 'Endpoint' `
        -Name 'Real-Time Protection Enforced via Intune' `
        -Status $mde002Status `
        -Detail $mde002Detail `
        -Recommendation 'Create a Windows Endpoint Protection profile in Intune with real-time monitoring enabled. Do not rely on device defaults.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/antivirus-microsoft-defender-settings-windows' `
        -CISControl 'CIS 8.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-003: Cloud-delivered protection enabled
    # -------------------------------------------------------------------------
    $cloudProtectionEnabled = $false
    foreach ($profile in $windowsDefenderProfiles) {
        try {
            $profileDetail = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($profile.id)" `
                -ErrorAction Stop
            if ($profileDetail.defenderCloudBlockLevel -ne $null -and
                $profileDetail.defenderCloudBlockLevel -ne 'notConfigured') {
                $cloudProtectionEnabled = $true
                break
            }
            if ($profileDetail.defenderCloudExtendedTimeout -ne $null) {
                $cloudProtectionEnabled = $true
                break
            }
        }
        catch {
            Write-Verbose "Could not fetch profile detail for $($profile.displayName): $_"
        }
    }

    if ($windowsDefenderProfiles.Count -eq 0) {
        $mde003Status = 'MEDIUM'
        $mde003Detail = 'No Defender configuration profiles found — cloud-delivered protection cannot be verified.'
    }
    elseif (-not $cloudProtectionEnabled) {
        $mde003Status = 'MEDIUM'
        $mde003Detail = 'Cloud-delivered protection (defenderCloudBlockLevel) not explicitly configured in any Intune Defender profile.'
    }
    else {
        $mde003Status = 'PASS'
        $mde003Detail = 'Cloud-delivered protection level is configured in a Defender Intune profile.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-003' `
        -Category 'Endpoint' `
        -Name 'Cloud-Delivered Protection Enabled' `
        -Status $mde003Status `
        -Detail $mde003Detail `
        -Recommendation 'Set defenderCloudBlockLevel to "high" in Windows Defender profile. Cloud protection provides faster detection of new threats.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/antivirus-microsoft-defender-settings-windows' `
        -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-004: Tamper protection enforced
    # -------------------------------------------------------------------------
    $tamperProtectionEnabled = $false

    # Check endpoint security intents (newer Endpoint Security profiles)
    try {
        $intentsUri = 'https://graph.microsoft.com/v1.0/deviceManagement/intents?$top=100'
        $intentsResp = Invoke-MgGraphRequest -Method GET -Uri $intentsUri -ErrorAction Stop
        $intents = $intentsResp.value

        $tamperIntents = @($intents | Where-Object {
            $_.displayName -match 'Tamper|Defender|Antivirus' -or
            $_.templateId -match 'antivirus'
        })

        foreach ($intent in $tamperIntents) {
            try {
                $settingsUri = "https://graph.microsoft.com/v1.0/deviceManagement/intents/$($intent.id)/settings"
                $settingsResp = Invoke-MgGraphRequest -Method GET -Uri $settingsUri -ErrorAction Stop
                $tamperSetting = $settingsResp.value | Where-Object {
                    $_.definitionId -match 'tamperProtection' -or $_.id -match 'tamper'
                }
                if ($tamperSetting -and $tamperSetting.value -eq $true) {
                    $tamperProtectionEnabled = $true
                    break
                }
            }
            catch {
                Write-Verbose "Could not fetch settings for intent $($intent.displayName): $_"
            }
        }
    }
    catch {
        Write-Verbose "Could not retrieve intents: $_"
    }

    # Also check device configs for tamper protection setting
    if (-not $tamperProtectionEnabled) {
        foreach ($profile in $windowsDefenderProfiles) {
            try {
                $profileDetail = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($profile.id)" `
                    -ErrorAction Stop
                if ($profileDetail.defenderTamperProtection -eq 'enable' -or
                    $profileDetail.tamperProtection -eq $true) {
                    $tamperProtectionEnabled = $true
                    break
                }
            }
            catch {
                Write-Verbose "Could not fetch profile detail for $($profile.displayName): $_"
            }
        }
    }

    $mde004Status = if ($tamperProtectionEnabled) { 'PASS' } else { 'HIGH' }
    $mde004Detail = if ($tamperProtectionEnabled) {
        'Tamper protection is enforced via an Intune Endpoint Security or device configuration profile.'
    }
    else {
        'Tamper protection is not explicitly enforced via Intune. Attackers or users can disable Defender AV if local admin.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-004' `
        -Category 'Endpoint' `
        -Name 'Tamper Protection Enforced' `
        -Status $mde004Status `
        -Detail $mde004Detail `
        -Recommendation 'Enable tamper protection in an Intune Endpoint Security Antivirus policy. This prevents local modification of Defender settings.' `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection' `
        -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-005: Attack Surface Reduction rules configured
    # -------------------------------------------------------------------------
    $asrProfiles = @($deviceConfigs | Where-Object {
        $_.'@odata.type' -match 'windows10EndpointProtection' -or
        $_.displayName -match 'ASR|Attack Surface|Attack surface'
    })

    $asrConfigured = $false
    $asrAuditOnly  = $false

    foreach ($profile in $asrProfiles) {
        try {
            $profileDetail = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($profile.id)" `
                -ErrorAction Stop
            # ASR rules are in defenderAttackSurfaceReductionExcludedPaths or
            # defenderGuardedFoldersAllowedAppPaths, or the OMA-URI custom settings
            $asrRuleProperties = $profileDetail.PSObject.Properties | Where-Object {
                $_.Name -match 'defenderAsr|attackSurface|GuardMyFolders'
            }
            if ($asrRuleProperties.Count -gt 0) {
                $asrConfigured = $true
                # If all values are 'auditMode', flag it
                $blockRules = @($asrRuleProperties | Where-Object { $_.Value -eq 'block' })
                if ($blockRules.Count -gt 0) {
                    $asrAuditOnly = $false
                }
                else {
                    $asrAuditOnly = $true
                }
                break
            }
        }
        catch {
            Write-Verbose "Could not fetch ASR profile detail for $($profile.displayName): $_"
        }
    }

    if (-not $asrConfigured) {
        $mde005Status = 'HIGH'
        $mde005Detail = 'No Attack Surface Reduction rules found in Intune device configuration profiles.'
    }
    elseif ($asrAuditOnly) {
        $mde005Status = 'MEDIUM'
        $mde005Detail = 'ASR rules found but configured in audit mode only — no enforcement. Audit mode is acceptable during piloting but should not remain permanent.'
    }
    else {
        $mde005Status = 'PASS'
        $mde005Detail = 'ASR rules are configured with enforcement (block mode) in at least one Intune profile.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-005' `
        -Category 'Endpoint' `
        -Name 'Attack Surface Reduction Rules Configured' `
        -Status $mde005Status `
        -Detail $mde005Detail `
        -Recommendation 'Enable ASR rules in Intune Endpoint Security. Start in audit mode, review events, then switch to block. Key rules: block Office from creating child processes, block credential stealing from LSASS.' `
        -Reference 'https://learn.microsoft.com/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-deployment' `
        -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # MDE-006: Firewall policy configured via Intune
    # -------------------------------------------------------------------------
    $firewallProfiles = @($deviceConfigs | Where-Object {
        $_.'@odata.type' -match 'windows10EndpointProtection' -or
        $_.displayName -match 'Firewall'
    })

    $firewallEnforced = $false
    foreach ($profile in $firewallProfiles) {
        try {
            $profileDetail = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($profile.id)" `
                -ErrorAction Stop
            if ($profileDetail.firewallEnabled -eq $true -or
                $profileDetail.defenderFirewallEnabled -eq $true -or
                $null -ne $profileDetail.firewallProfileDomain) {
                $firewallEnforced = $true
                break
            }
        }
        catch {
            Write-Verbose "Could not fetch firewall profile detail for $($profile.displayName): $_"
        }
    }

    # Also check Endpoint Security firewall policies (intents)
    if (-not $firewallEnforced) {
        try {
            $fwIntentsUri = 'https://graph.microsoft.com/v1.0/deviceManagement/intents?$top=100'
            $fwIntentsResp = Invoke-MgGraphRequest -Method GET -Uri $fwIntentsUri -ErrorAction Stop
            $fwIntents = @($fwIntentsResp.value | Where-Object { $_.displayName -match 'Firewall' })
            if ($fwIntents.Count -gt 0) {
                $firewallEnforced = $true
            }
        }
        catch {
            Write-Verbose "Could not retrieve intents for firewall check: $_"
        }
    }

    $mde006Status = if ($firewallEnforced) { 'PASS' } else { 'HIGH' }
    $mde006Detail = if ($firewallEnforced) {
        'Firewall policy is enforced via an Intune Endpoint Protection or Endpoint Security profile.'
    }
    else {
        'No Intune-managed firewall policy found. Windows Firewall state relies entirely on local device configuration.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'MDE-006' `
        -Category 'Endpoint' `
        -Name 'Firewall Policy Configured via Intune' `
        -Status $mde006Status `
        -Detail $mde006Detail `
        -Recommendation 'Configure a Windows Firewall policy via Intune Endpoint Security. Enable firewall for Domain, Private, and Public profiles. Block inbound connections by default.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/endpoint-security-firewall-policy' `
        -CISControl 'CIS 12.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
