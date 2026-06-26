#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.DeviceManagement, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Audits Intune device configuration: update policies, enrollment, MDM scope, profile coverage. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgDeviceManagementDeviceConfiguration -All and
    related Microsoft.Graph.DeviceManagement cmdlets instead of raw
    Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    Get-MgDeviceManagementDeviceConfiguration is the PowerShell equivalent of
    /deviceManagement/deviceConfigurations. It supports -All for pagination and
    -Filter for OData filtering.

    NOTE on Windows Update Rings (DEV-001):
    Windows Update ring-specific filtering (windowsUpdateForBusinessConfiguration
    OData type) works via Get-MgDeviceManagementDeviceConfiguration but the
    -Filter on @odata.type is not always supported by all Graph endpoints.
    This module uses client-side filtering on the ODataType property.

    NOTE on Update Ring-specific endpoints:
    Endpoints like /deviceManagement/windowsQualityUpdatePolicies are Intune-specific
    and do NOT have a Get-Mg* cmdlet equivalent — these emit INFO stubs.

    SEE ALSO (Graph variant):
        scripts/modules/Endpoint/Test-DeviceConfig.ps1

    Required connection:
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All","DeviceManagementManagedDevices.Read.All","Policy.Read.All"

    Required scopes:
        DeviceManagementConfiguration.Read.All
        DeviceManagementManagedDevices.Read.All
        Policy.Read.All  (for MDM scope and CA cross-reference)

    Required modules:
        Microsoft.Graph.DeviceManagement
        Microsoft.Graph.Identity.SignIns  (for CA policy cross-check)

    License: E3 minimum (Intune)
    SC-300 Domain: Device Management

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-DeviceConfig {
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
            -CheckId 'DEV-000' `
            -Category 'Endpoint' `
            -Name 'Device Configuration Profile Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/configuration/device-profile-monitor' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # DEV-001: Windows Update policy (Update Rings)
    # Client-side filter on AdditionalProperties['@odata.type']
    # windowsQualityUpdatePolicies endpoint has no Get-Mg* cmdlet — INFO stub
    # -------------------------------------------------------------------------
    try {
        $updateRings = @($deviceConfigs | Where-Object {
            $_.AdditionalProperties['@odata.type'] -match 'windowsUpdateForBusinessConfiguration'
        })

        # INFO: windowsQualityUpdatePolicies has no Get-Mg* equivalent
        $qualityPoliciesNote = 'NOTE: Windows Quality Update Policies (/deviceManagement/windowsQualityUpdatePolicies) have no Get-Mg* cmdlet. Check manually via Intune portal or use the Graph variant.'

        $totalUpdatePolicies = $updateRings.Count

        if ($totalUpdatePolicies -eq 0) {
            $dev001Status = 'HIGH'
            $dev001Detail = "No Windows Update ring policies found. Devices may defer updates indefinitely. $qualityPoliciesNote"
        }
        else {
            $longDeferralRings = @($updateRings | Where-Object {
                $_.AdditionalProperties['qualityUpdatesDeferralPeriodInDays'] -gt 30 -or
                $_.AdditionalProperties['featureUpdatesDeferralPeriodInDays'] -gt 90
            })

            $dev001Status = if ($longDeferralRings.Count -gt 0) { 'MEDIUM' } else { 'PASS' }
            $dev001Detail = "Found $($updateRings.Count) Windows Update ring(s)."
            if ($longDeferralRings.Count -gt 0) {
                $longNames = ($longDeferralRings | ForEach-Object { $_.DisplayName }) -join ', '
                $dev001Detail += " Rings with long deferral (quality >30d or feature >90d): $longNames."
            }
            $dev001Detail += " $qualityPoliciesNote"
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
            -Detail "Check skipped: API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/windows-update-for-business-configure' `
            -CISControl 'CIS 7.4' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-002: Device enrollment restrictions
    # Get-MgDeviceManagementDeviceEnrollmentConfiguration
    # -------------------------------------------------------------------------
    try {
        $enrollConfigs = Get-MgDeviceManagementDeviceEnrollmentConfiguration -All -ErrorAction Stop

        $platformRestrictions = @($enrollConfigs | Where-Object {
            $_.AdditionalProperties['@odata.type'] -match 'deviceEnrollmentPlatformRestrictionsConfiguration' -or
            $_.AdditionalProperties['@odata.type'] -match 'deviceEnrollmentPlatformRestriction'
        })

        if ($platformRestrictions.Count -eq 0) {
            $dev002Status = 'HIGH'
            $dev002Detail = 'No device enrollment platform restriction configurations found. All device types and ownership types (including personal BYOD) are allowed by default.'
        }
        else {
            # Check if personal Windows device enrollment is blocked
            $personalAllowed = $false
            foreach ($config in $platformRestrictions) {
                $winRestrict = $config.AdditionalProperties['windowsRestriction']
                if ($winRestrict -and $winRestrict['personalDeviceEnrollmentBlocked'] -eq $false) {
                    $personalAllowed = $true
                    break
                }
            }

            if ($personalAllowed) {
                $dev002Status = 'HIGH'
                $dev002Detail = "Enrollment restrictions exist ($($platformRestrictions.Count) configuration(s)) but personal device enrollment is permitted for Windows without restriction."
            }
            else {
                $dev002Status = 'PASS'
                $dev002Detail = "Enrollment restrictions configured ($($platformRestrictions.Count) configuration(s)). Personal device enrollment appears restricted."
            }
        }

        $results.Add((New-CheckResult `
            -CheckId 'DEV-002' `
            -Category 'Endpoint' `
            -Name 'Device Enrollment Restrictions' `
            -Status $dev002Status `
            -Detail $dev002Detail `
            -Recommendation 'Configure enrollment restrictions to block personal (BYOD) devices or require device compliance before enrollment.' `
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
            -Detail "Check skipped: API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/enrollment/enrollment-restrictions-set' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-003: AutoEnrollment / MDM scope
    # Get-MgPolicyMobileDeviceManagementPolicy
    # -------------------------------------------------------------------------
    try {
        $mdmPolicies = Get-MgPolicyMobileDeviceManagementPolicy -All -ErrorAction Stop

        $intunePolicy = $mdmPolicies | Select-Object -First 1

        if ($null -eq $intunePolicy) {
            $dev003Status = 'HIGH'
            $dev003Detail = 'No MDM auto-enrollment policy found. Devices joining Entra ID will not automatically enroll in Intune.'
        }
        else {
            switch ($intunePolicy.AppliesTo) {
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
                    $dev003Detail = "MDM auto-enrollment scope: '$($intunePolicy.AppliesTo)'."
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
            -Detail "Check skipped: API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/enrollment/windows-enroll' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-004: Enrolled device count by platform (INFO)
    # Get-MgDeviceManagementManagedDevice -All
    # -------------------------------------------------------------------------
    try {
        $allDevices = Get-MgDeviceManagementManagedDevice `
            -All `
            -Property 'operatingSystem,managedDeviceOwnerType' `
            -ErrorAction Stop

        $byOS = $allDevices | Group-Object -Property OperatingSystem | Sort-Object Count -Descending |
                ForEach-Object { "$($_.Name): $($_.Count)" }
        $byOwner = $allDevices | Group-Object -Property ManagedDeviceOwnerType | Sort-Object Count -Descending |
                   ForEach-Object { "$($_.Name): $($_.Count)" }

        $results.Add((New-CheckResult `
            -CheckId 'DEV-004' `
            -Category 'Endpoint' `
            -Name 'Enrolled Device Count by Platform' `
            -Status 'INFO' `
            -Detail "Total managed devices: $(($allDevices | Measure-Object).Count). By OS: $($byOS -join ', '). By ownership: $($byOwner -join ', ')." `
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
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/remote-actions/device-inventory' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-005: Device configuration profile coverage (state summary)
    # Invoke-MgGraphRequest fallback — no Get-Mg* for deviceConfigurationDeviceStateSummaries
    # -------------------------------------------------------------------------
    try {
        $profileStatusResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurationDeviceStateSummaries' `
            -ErrorAction Stop

        $successCount  = [int]($profileStatusResp.successDeviceCount)
        $conflictCount = [int]($profileStatusResp.conflictDeviceCount)
        $errorCount    = [int]($profileStatusResp.errorDeviceCount)
        $totalCount    = $successCount + $conflictCount + $errorCount + [int]($profileStatusResp.notApplicableDeviceCount)

        $problemCount = $conflictCount + $errorCount
        $problemPct   = if ($totalCount -gt 0) { [math]::Round(($problemCount / $totalCount) * 100, 1) } else { 0 }

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
            -Detail "Check skipped: API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/configuration/device-profile-monitor' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # DEV-006: Conditional Access — require enrolled/compliant device
    # Get-MgIdentityConditionalAccessPolicy -All
    # -------------------------------------------------------------------------
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        $enabledPolicies = @($caPolicies | Where-Object { $_.State -eq 'enabled' })

        $deviceCompliancePolicies = @($enabledPolicies | Where-Object {
            $_.GrantControls.BuiltInControls -contains 'compliantDevice' -or
            $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice'
        })

        if ($deviceCompliancePolicies.Count -eq 0) {
            $dev006Status = 'HIGH'
            $dev006Detail = 'No enabled Conditional Access policy requires a compliant or domain-joined device for corporate access. Non-managed devices can access resources if they pass MFA.'
        }
        else {
            $policyNames  = ($deviceCompliancePolicies | ForEach-Object { $_.DisplayName }) -join ', '
            $dev006Status = 'PASS'
            $dev006Detail = "$($deviceCompliancePolicies.Count) CA policy/policies require compliant or domain-joined device: $policyNames."
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
            -Detail "Check skipped: API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-policy-compliant-device' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
