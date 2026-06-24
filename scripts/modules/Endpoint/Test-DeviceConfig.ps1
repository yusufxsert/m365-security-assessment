#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Intune device configuration: update policies, enrollment restrictions,
    MDM scope, device counts, profile coverage, and CA device compliance cross-check.

.DESCRIPTION
    Test-DeviceConfig evaluates Windows Update ring policies, enrollment restriction
    settings, MDM auto-enrollment scope, enrolled device inventory, configuration
    profile deployment success/conflict/error rates, and whether any Conditional
    Access policy requires a compliant or enrolled device.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        DeviceManagementConfiguration.Read.All
        Policy.Read.All  (for CA cross-reference)

    License Required: E3 minimum (Intune)
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
#>

function Test-DeviceConfig {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # DEV-001: Windows Update policy (Update Rings)
    # -------------------------------------------------------------------------
    try {
        $updateRingsUri = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$filter=isof(''microsoft.graph.windowsUpdateForBusinessConfiguration'')&$top=50'
        $updateRingsResp = Invoke-MgGraphRequest -Method GET -Uri $updateRingsUri -ErrorAction Stop
        $updateRings = $updateRingsResp.value

        # Also check quality update policies (Autopatch / newer API)
        $qualityPoliciesUri = 'https://graph.microsoft.com/v1.0/deviceManagement/windowsQualityUpdatePolicies?$top=50'
        try {
            $qualPoliciesResp = Invoke-MgGraphRequest -Method GET -Uri $qualityPoliciesUri -ErrorAction Stop
            $qualityPolicies = $qualPoliciesResp.value
        }
        catch {
            $qualityPolicies = @()
            Write-Verbose "windowsQualityUpdatePolicies API not available or no permission: $_"
        }

        $totalUpdatePolicies = $updateRings.Count + $qualityPolicies.Count

        if ($totalUpdatePolicies -eq 0) {
            $dev001Status = 'HIGH'
            $dev001Detail = 'No Windows Update ring policies or quality update policies found. Devices may defer updates indefinitely or use default Windows Update settings.'
        }
        else {
            # Check deferral settings on update rings
            $longDeferralRings = @($updateRings | Where-Object {
                $_.qualityUpdatesDeferralPeriodInDays -gt 30 -or
                $_.featureUpdatesDeferralPeriodInDays -gt 90
            })

            $dev001Status = if ($longDeferralRings.Count -gt 0) { 'MEDIUM' } else { 'PASS' }
            $dev001Detail = "Found $($updateRings.Count) Windows Update ring(s) and $($qualityPolicies.Count) quality update policy/policies."
            if ($longDeferralRings.Count -gt 0) {
                $dev001Detail += " Rings with long deferral (quality >30d or feature >90d): $($longDeferralRings | ForEach-Object { $_.displayName } | Join-String -Separator ', ')."
            }
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEV-001' `
            -Category 'Endpoint' `
            -Name 'Windows Update Policy Configured' `
            -Status $dev001Status `
            -Detail $dev001Detail `
            -Recommendation 'Configure Windows Update rings in Intune. Recommended: quality updates defer 0-7 days, feature updates 30-60 days. Consider Windows Autopatch for automated patching.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/windows-update-for-business-configure' `
            -CISControl 'CIS 7.4' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEV-001' `
            -Category 'Endpoint' `
            -Name 'Windows Update Policy Configured' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementConfiguration.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/windows-update-for-business-configure' `
            -CISControl 'CIS 7.4' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-002: Device enrollment restrictions
    # -------------------------------------------------------------------------
    try {
        $enrollRestUri = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations?$top=100'
        $enrollRestResp = Invoke-MgGraphRequest -Method GET -Uri $enrollRestUri -ErrorAction Stop
        $enrollConfigs = $enrollRestResp.value

        $platformRestrictions = @($enrollConfigs | Where-Object {
            $_.'@odata.type' -match 'deviceEnrollmentPlatformRestrictionsConfiguration' -or
            $_.'@odata.type' -match 'deviceEnrollmentPlatformRestriction'
        })

        $personalAllowed = $false
        foreach ($config in $platformRestrictions) {
            try {
                $configDetail = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceEnrollmentConfigurations/$($config.id)" `
                    -ErrorAction Stop
                # Check if personal Windows devices are allowed without restriction
                if ($configDetail.windowsRestriction.personalDeviceEnrollmentBlocked -eq $false -or
                    $configDetail.windowsMobileRestriction.personalDeviceEnrollmentBlocked -eq $false) {
                    $personalAllowed = $true
                    break
                }
            }
            catch {
                Write-Verbose "Could not fetch enrollment config detail for $($config.displayName): $_"
            }
        }

        if ($platformRestrictions.Count -eq 0) {
            $dev002Status = 'HIGH'
            $dev002Detail = 'No device enrollment platform restriction configurations found. All device types and ownership types (including personal BYOD) are allowed by default.'
        }
        elseif ($personalAllowed) {
            $dev002Status = 'HIGH'
            $dev002Detail = "Enrollment restrictions exist ($($platformRestrictions.Count) configuration(s)) but personal device enrollment is permitted for Windows without restriction."
        }
        else {
            $dev002Status = 'PASS'
            $dev002Detail = "Enrollment restrictions configured ($($platformRestrictions.Count) configuration(s)). Personal device enrollment appears restricted."
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEV-002' `
            -Category 'Endpoint' `
            -Name 'Device Enrollment Restrictions' `
            -Status $dev002Status `
            -Detail $dev002Detail `
            -Recommendation 'Configure enrollment restrictions to block personal (BYOD) devices or require device compliance before enrollment. Define clearly which platforms are allowed.' `
            -Reference 'https://learn.microsoft.com/mem/intune/enrollment/enrollment-restrictions-set' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEV-002' `
            -Category 'Endpoint' `
            -Name 'Device Enrollment Restrictions' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementConfiguration.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/enrollment/enrollment-restrictions-set' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-003: AutoEnrollment / MDM scope
    # -------------------------------------------------------------------------
    try {
        $mdmPoliciesUri = 'https://graph.microsoft.com/v1.0/policies/mobileDeviceManagementPolicies'
        $mdmPoliciesResp = Invoke-MgGraphRequest -Method GET -Uri $mdmPoliciesUri -ErrorAction Stop
        $mdmPolicies = if ($mdmPoliciesResp.value) { $mdmPoliciesResp.value } else { @($mdmPoliciesResp) }

        $intunePolicy = $mdmPolicies | Where-Object { $_.appliesTo -ne $null } | Select-Object -First 1

        if ($null -eq $intunePolicy) {
            $dev003Status = 'HIGH'
            $dev003Detail = 'No MDM auto-enrollment policy found. Devices joining Entra ID will not automatically enroll in Intune.'
        }
        else {
            switch ($intunePolicy.appliesTo) {
                'none' {
                    $dev003Status = 'HIGH'
                    $dev003Detail = "MDM auto-enrollment scope is 'none'. No devices will auto-enroll in Intune when joining Entra ID."
                }
                'some' {
                    $dev003Status = 'MEDIUM'
                    $dev003Detail = "MDM auto-enrollment scope is 'some' (partial). Only devices in selected groups will auto-enroll. Risk of coverage gaps."
                }
                'all' {
                    $dev003Status = 'PASS'
                    $dev003Detail = "MDM auto-enrollment scope is 'all'. All devices joining Entra ID will auto-enroll in Intune."
                }
                default {
                    $dev003Status = 'INFO'
                    $dev003Detail = "MDM auto-enrollment scope: '$($intunePolicy.appliesTo)'."
                }
            }
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEV-003' `
            -Category 'Endpoint' `
            -Name 'MDM Auto-Enrollment Scope' `
            -Status $dev003Status `
            -Detail $dev003Detail `
            -Recommendation "Set MDM auto-enrollment scope to 'all' to ensure every device that joins Entra ID is automatically managed by Intune." `
            -Reference 'https://learn.microsoft.com/mem/intune/enrollment/windows-enroll' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEV-003' `
            -Category 'Endpoint' `
            -Name 'MDM Auto-Enrollment Scope' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/enrollment/windows-enroll' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-004: Enrolled device count by platform (INFO)
    # -------------------------------------------------------------------------
    try {
        $allDevUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=operatingSystem,managedDeviceOwnerType&`$top=999"
        $allDevResp = Invoke-MgGraphRequest -Method GET -Uri $allDevUri -ErrorAction Stop
        $allDevices = [System.Collections.Generic.List[object]]::new()
        foreach ($d in $allDevResp.value) { $allDevices.Add($d) }
        $nextLink = $allDevResp.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($d in $page.value) { $allDevices.Add($d) }
            $nextLink = $page.'@odata.nextLink'
        }

        $byOS = $allDevices | Group-Object -Property operatingSystem | Sort-Object Count -Descending |
                ForEach-Object { "$($_.Name): $($_.Count)" }
        $byOwner = $allDevices | Group-Object -Property managedDeviceOwnerType | Sort-Object Count -Descending |
                   ForEach-Object { "$($_.Name): $($_.Count)" }

        $results.Add((New-CheckResult `
            -CheckId 'DEV-004' `
            -Category 'Endpoint' `
            -Name 'Enrolled Device Count by Platform' `
            -Status 'INFO' `
            -Detail "Total managed devices: $($allDevices.Count). By OS: $($byOS -join ', '). By ownership: $($byOwner -join ', ')." `
            -Recommendation 'Use this inventory to ensure compliance and configuration policies cover all enrolled platforms and ownership types.' `
            -Reference 'https://learn.microsoft.com/mem/intune/remote-actions/device-inventory' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEV-004' `
            -Category 'Endpoint' `
            -Name 'Enrolled Device Count by Platform' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: DeviceManagementManagedDevices.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementManagedDevices.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/remote-actions/device-inventory' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-005: Device configuration profile coverage (error/conflict rate)
    # -------------------------------------------------------------------------
    try {
        $profileStatusUri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurationDeviceStateSummaries"
        $profileStatusResp = Invoke-MgGraphRequest -Method GET -Uri $profileStatusUri -ErrorAction Stop

        $successCount  = [int]($profileStatusResp.successDeviceCount)
        $conflictCount = [int]($profileStatusResp.conflictDeviceCount)
        $errorCount    = [int]($profileStatusResp.errorDeviceCount)
        $totalCount    = $successCount + $conflictCount + $errorCount + [int]($profileStatusResp.notApplicableDeviceCount)

        $problemCount  = $conflictCount + $errorCount
        $problemPct    = if ($totalCount -gt 0) { [math]::Round(($problemCount / $totalCount) * 100, 1) } else { 0 }

        $dev005Status = if ($problemPct -gt 10) { 'HIGH' } elseif ($problemPct -gt 5) { 'MEDIUM' } else { 'PASS' }
        $dev005Detail = "Device configuration profile state summary — Success: $successCount, Conflict: $conflictCount, Error: $errorCount. Problem rate: $problemPct% of $totalCount devices."

        $results.Add((New-CheckResult `
            -CheckId 'DEV-005' `
            -Category 'Endpoint' `
            -Name 'Device Configuration Profile Coverage' `
            -Status $dev005Status `
            -Detail $dev005Detail `
            -Recommendation 'Investigate devices with conflict or error configuration states. Common causes: conflicting profiles, insufficient permissions, or device not checking in.' `
            -Reference 'https://learn.microsoft.com/mem/intune/configuration/device-profile-monitor' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEV-005' `
            -Category 'Endpoint' `
            -Name 'Device Configuration Profile Coverage' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementConfiguration.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/configuration/device-profile-monitor' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-006: Conditional Access — require enrolled/compliant device
    # -------------------------------------------------------------------------
    try {
        $caPoliciesUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250'
        $caPoliciesResp = Invoke-MgGraphRequest -Method GET -Uri $caPoliciesUri -ErrorAction Stop
        $caPolicies = $caPoliciesResp.value
        $nextLink = $caPoliciesResp.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $caPolicies += $page.value
            $nextLink = $page.'@odata.nextLink'
        }

        $enabledPolicies = @($caPolicies | Where-Object { $_.state -eq 'enabled' })

        $deviceCompliancePolicies = @($enabledPolicies | Where-Object {
            $_.grantControls.builtInControls -contains 'compliantDevice' -or
            $_.grantControls.builtInControls -contains 'domainJoinedDevice'
        })

        if ($deviceCompliancePolicies.Count -eq 0) {
            $dev006Status = 'HIGH'
            $dev006Detail = "No enabled Conditional Access policy requires a compliant or domain-joined device for corporate access. Non-managed devices can access resources if they pass MFA."
        }
        else {
            $dev006Status = 'PASS'
            $dev006Detail = "$($deviceCompliancePolicies.Count) CA policy/policies require compliant or domain-joined device: $($deviceCompliancePolicies | ForEach-Object { $_.displayName } | Join-String -Separator ', ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEV-006' `
            -Category 'Endpoint' `
            -Name 'CA Policy Requires Compliant/Enrolled Device' `
            -Status $dev006Status `
            -Detail $dev006Detail `
            -Recommendation 'Create a Conditional Access policy requiring a compliant device (or Hybrid Azure AD joined) for access to all cloud apps. Pair with Intune compliance policies.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DEV-006' `
            -Category 'Endpoint' `
            -Name 'CA Policy Requires Compliant/Enrolled Device' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
