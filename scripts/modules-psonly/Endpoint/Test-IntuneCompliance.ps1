#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Audits Intune device compliance policies and non-compliant device inventory. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgDeviceManagementDeviceCompliancePolicy -All,
    Get-MgDeviceManagementDeviceCompliancePolicyDeviceStateSummary, and
    Get-MgDeviceManagementManagedDevice -All instead of raw Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    Microsoft.Graph.DeviceManagement provides native cmdlets for compliance policies and
    managed device inventory. Client-side filtering on AdditionalProperties is used where
    server-side OData filter on @odata.type is not reliable.

    SEE ALSO (Graph variant):
        scripts/modules/Endpoint/Test-IntuneCompliance.ps1

    Required connection:
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All","DeviceManagementManagedDevices.Read.All"

    Required scopes:
        DeviceManagementConfiguration.Read.All
        DeviceManagementManagedDevices.Read.All

    Required modules:
        Microsoft.Graph.DeviceManagement

    License: E3 (Intune Plan 1)
    SC-300 Domain: Device Management

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-IntuneCompliance {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all compliance policies once
    # -------------------------------------------------------------------------
    $compliancePolicies = $null
    try {
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'INT-000' `
            -Category 'Endpoint' `
            -Name 'Intune Compliance Policy Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $totalPolicies = ($compliancePolicies | Measure-Object).Count

    # -------------------------------------------------------------------------
    # INT-000: Compliance policies exist at all
    # -------------------------------------------------------------------------
    if ($totalPolicies -eq 0) {
        $results.Add((New-CheckResult `
            -CheckId 'INT-000' `
            -Category 'Endpoint' `
            -Name 'Intune Compliance Policies Exist' `
            -Status 'CRITICAL' `
            -Detail 'No Intune device compliance policies found. Without compliance policies, all devices are reported as compliant by default (or non-compliant if the default behavior is enabled), and Conditional Access device compliance controls cannot be enforced.' `
            -Recommendation 'Create compliance policies for each platform (Windows, iOS, Android, macOS). At minimum, require OS version, BitLocker, and screen lock PIN.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $results.Add((New-CheckResult `
        -CheckId 'INT-000' `
        -Category 'Endpoint' `
        -Name 'Intune Compliance Policies Exist' `
        -Status 'PASS' `
        -Detail "Found $totalPolicies device compliance policy/policies." `
        -Recommendation 'Ensure compliance policies cover all enrolled platforms. Verify each policy is assigned to all devices or appropriate groups.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
        -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # INT-001: Windows compliance — BitLocker required
    # Filter on @odata.type windows10CompliancePolicy
    # -------------------------------------------------------------------------
    $winPolicies = @($compliancePolicies | Where-Object {
        $_.AdditionalProperties['@odata.type'] -match 'windows10CompliancePolicy'
    })

    if ($winPolicies.Count -gt 0) {
        $noEncryption = @($winPolicies | Where-Object {
            $_.AdditionalProperties['storageRequireEncryption'] -ne $true
        })

        $int001Status = if ($noEncryption.Count -gt 0) { 'HIGH' } else { 'PASS' }
        $int001Detail = "Windows compliance policies: $($winPolicies.Count). Policies missing BitLocker requirement (storageRequireEncryption): $($noEncryption.Count)."
        if ($noEncryption.Count -gt 0) {
            $int001Detail += " Affected policies: $($noEncryption | ForEach-Object { $_.DisplayName } | Join-String -Separator ', ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'INT-001' `
            -Category 'Endpoint' `
            -Name 'Windows Compliance — BitLocker Required' `
            -Status $int001Status `
            -Detail $int001Detail `
            -Recommendation "Enable 'Require BitLocker encryption' (storageRequireEncryption) in all Windows compliance policies. BitLocker protects data at rest on lost or stolen devices." `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-windows' `
            -CISControl 'CIS 3.6' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @($noEncryption | ForEach-Object { $_.DisplayName })))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'INT-001' `
            -Category 'Endpoint' `
            -Name 'Windows Compliance — BitLocker Required' `
            -Status 'HIGH' `
            -Detail 'No Windows compliance policies found (windows10CompliancePolicy). Windows devices are not evaluated for BitLocker compliance.' `
            -Recommendation 'Create a Windows 10/11 compliance policy requiring BitLocker encryption.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-windows' `
            -CISControl 'CIS 3.6' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # INT-002: Windows compliance — OS version minimum
    # -------------------------------------------------------------------------
    if ($winPolicies.Count -gt 0) {
        $noOsMin = @($winPolicies | Where-Object {
            [string]::IsNullOrEmpty($_.AdditionalProperties['osMinimumVersion'])
        })

        $int002Status = if ($noOsMin.Count -gt 0) { 'MEDIUM' } else { 'PASS' }
        $int002Detail = "Windows compliance policies: $($winPolicies.Count). Policies without OS minimum version: $($noOsMin.Count)."
        if ($noOsMin.Count -gt 0) {
            $int002Detail += " Affected: $($noOsMin | ForEach-Object { $_.DisplayName } | Join-String -Separator ', ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'INT-002' `
            -Category 'Endpoint' `
            -Name 'Windows Compliance — OS Minimum Version' `
            -Status $int002Status `
            -Detail $int002Detail `
            -Recommendation "Set a minimum Windows version in compliance policies (e.g., 10.0.22621 for Windows 11 22H2). This blocks non-patched devices from accessing corporate resources." `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-windows' `
            -CISControl 'CIS 7.4' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @($noOsMin | ForEach-Object { $_.DisplayName })))
    }

    # -------------------------------------------------------------------------
    # INT-003: Windows compliance — Antivirus required
    # -------------------------------------------------------------------------
    if ($winPolicies.Count -gt 0) {
        $noAv = @($winPolicies | Where-Object {
            $_.AdditionalProperties['antivirusRequired'] -ne $true
        })

        $int003Status = if ($noAv.Count -gt 0) { 'HIGH' } else { 'PASS' }
        $int003Detail = "Windows compliance policies: $($winPolicies.Count). Policies without antivirus requirement: $($noAv.Count)."
        if ($noAv.Count -gt 0) {
            $int003Detail += " Affected: $($noAv | ForEach-Object { $_.DisplayName } | Join-String -Separator ', ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'INT-003' `
            -Category 'Endpoint' `
            -Name 'Windows Compliance — Antivirus Required' `
            -Status $int003Status `
            -Detail $int003Detail `
            -Recommendation "Enable 'Antivirus required' in Windows compliance policies. This enforces that any approved antivirus is active before the device can access corporate resources." `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-windows' `
            -CISControl 'CIS 10.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @($noAv | ForEach-Object { $_.DisplayName })))
    }

    # -------------------------------------------------------------------------
    # INT-004: iOS compliance — screen lock and passcode
    # -------------------------------------------------------------------------
    $iosPolicies = @($compliancePolicies | Where-Object {
        $_.AdditionalProperties['@odata.type'] -match 'iosCompliancePolicy'
    })

    if ($iosPolicies.Count -gt 0) {
        $noPasscode = @($iosPolicies | Where-Object {
            $_.AdditionalProperties['passcodeRequired'] -ne $true
        })

        $int004Status = if ($noPasscode.Count -gt 0) { 'HIGH' } else { 'PASS' }
        $int004Detail = "iOS compliance policies: $($iosPolicies.Count). Policies without passcode requirement: $($noPasscode.Count)."
        if ($noPasscode.Count -gt 0) {
            $int004Detail += " Affected: $($noPasscode | ForEach-Object { $_.DisplayName } | Join-String -Separator ', ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'INT-004' `
            -Category 'Endpoint' `
            -Name 'iOS Compliance — Passcode Required' `
            -Status $int004Status `
            -Detail $int004Detail `
            -Recommendation "Enable passcode requirement in all iOS compliance policies. This is a basic control that prevents unauthorized physical access to mobile devices." `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-ios' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @($noPasscode | ForEach-Object { $_.DisplayName })))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'INT-004' `
            -Category 'Endpoint' `
            -Name 'iOS Compliance — Passcode Required' `
            -Status 'INFO' `
            -Detail 'No iOS compliance policies found. If iOS devices are enrolled in Intune, create an iOS compliance policy requiring a passcode.' `
            -Recommendation 'Create iOS compliance policies if iOS devices are managed. Require passcode and minimum OS version.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-ios' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # INT-005: Android compliance — screen lock
    # -------------------------------------------------------------------------
    $androidPolicies = @($compliancePolicies | Where-Object {
        $_.AdditionalProperties['@odata.type'] -match 'androidCompliancePolicy|androidDeviceOwnerCompliancePolicy|androidWorkProfileCompliancePolicy'
    })

    if ($androidPolicies.Count -gt 0) {
        $noScreenLock = @($androidPolicies | Where-Object {
            $_.AdditionalProperties['securityRequireVerifyApps'] -ne $true -and
            $_.AdditionalProperties['passwordRequired'] -ne $true
        })

        $int005Status = if ($noScreenLock.Count -gt 0) { 'HIGH' } else { 'PASS' }
        $int005Detail = "Android compliance policies: $($androidPolicies.Count). Policies without password/screen lock requirement: $($noScreenLock.Count)."
        if ($noScreenLock.Count -gt 0) {
            $int005Detail += " Affected: $($noScreenLock | ForEach-Object { $_.DisplayName } | Join-String -Separator ', ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'INT-005' `
            -Category 'Endpoint' `
            -Name 'Android Compliance — Password/Screen Lock Required' `
            -Status $int005Status `
            -Detail $int005Detail `
            -Recommendation 'Enable password requirement in all Android compliance policies. This prevents unauthorized physical access to corporate data on mobile devices.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-android' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @($noScreenLock | ForEach-Object { $_.DisplayName })))
    }

    # -------------------------------------------------------------------------
    # INT-006: Non-compliant devices (managed device inventory)
    # Get-MgDeviceManagementManagedDevice -All with complianceState filter
    # -------------------------------------------------------------------------
    try {
        $allDevices = Get-MgDeviceManagementManagedDevice `
            -All `
            -Property 'deviceName,operatingSystem,complianceState,lastSyncDateTime,userPrincipalName' `
            -ErrorAction Stop

        $totalDevices    = ($allDevices | Measure-Object).Count
        $noncompliant    = @($allDevices | Where-Object { $_.ComplianceState -eq 'noncompliant' })
        $unknown         = @($allDevices | Where-Object { $_.ComplianceState -eq 'unknown' })
        $configManager   = @($allDevices | Where-Object { $_.ComplianceState -eq 'configManager' })

        $staleThreshold  = (Get-Date).AddDays(-30)
        $staleDevices    = @($allDevices | Where-Object {
            $_.LastSyncDateTime -and [datetime]$_.LastSyncDateTime -lt $staleThreshold
        })

        $noncompliantPct = if ($totalDevices -gt 0) { [math]::Round(($noncompliant.Count / $totalDevices) * 100, 1) } else { 0 }

        if ($noncompliantPct -gt 20) {
            $int006Status = 'CRITICAL'
        }
        elseif ($noncompliantPct -gt 10) {
            $int006Status = 'HIGH'
        }
        elseif ($noncompliantPct -gt 5) {
            $int006Status = 'MEDIUM'
        }
        elseif ($noncompliant.Count -gt 0) {
            $int006Status = 'LOW'
        }
        else {
            $int006Status = 'PASS'
        }

        $int006Detail = "Total managed devices: $totalDevices. Non-compliant: $($noncompliant.Count) ($noncompliantPct%). Unknown compliance: $($unknown.Count). Stale (no sync in 30d): $($staleDevices.Count)."

        $results.Add((New-CheckResult `
            -CheckId 'INT-006' `
            -Category 'Endpoint' `
            -Name 'Non-Compliant Devices' `
            -Status $int006Status `
            -Detail $int006Detail `
            -Recommendation 'Investigate non-compliant devices. Common causes: expired OS, missing BitLocker, or inactive Defender. Use Intune reports to identify and remediate. Consider blocking non-compliant devices from corporate resources via Conditional Access.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-monitor' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @($noncompliant | Select-Object -First 20 | ForEach-Object { "$($_.DeviceName) ($($_.OperatingSystem)) — $($_.UserPrincipalName)" })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'INT-006' `
            -Category 'Endpoint' `
            -Name 'Non-Compliant Devices' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: DeviceManagementManagedDevices.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All".' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-monitor' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # INT-007: Mark non-compliant device action (grace period / mark compliant)
    # Check if compliance policies have notifyUser or retireDevice actions
    # -------------------------------------------------------------------------
    $policiesWithActions = @($compliancePolicies | Where-Object {
        $_.ScheduledActionsForRule -and $_.ScheduledActionsForRule.Count -gt 0 -and
        $_.ScheduledActionsForRule[0].ScheduledActionConfigurations.Count -gt 0
    })

    $policiesWithRetire = @($compliancePolicies | Where-Object {
        $_.ScheduledActionsForRule | ForEach-Object { $_.ScheduledActionConfigurations } |
        Where-Object { $_.ActionType -eq 'retire' }
    })

    $policiesWithNotify = @($compliancePolicies | Where-Object {
        $_.ScheduledActionsForRule | ForEach-Object { $_.ScheduledActionConfigurations } |
        Where-Object { $_.ActionType -eq 'notification' }
    })

    if ($policiesWithActions.Count -eq 0) {
        $int007Status = 'MEDIUM'
        $int007Detail = "No compliance policies have automated non-compliance actions configured (retire, notification, etc.). Non-compliant devices are flagged but no automatic remediation or escalation occurs."
    }
    else {
        $int007Status = 'PASS'
        $int007Detail = "Compliance policies with automated actions: $($policiesWithActions.Count) of $totalPolicies. Policies with retire action: $($policiesWithRetire.Count). Policies with notification: $($policiesWithNotify.Count)."
    }

    $results.Add((New-CheckResult `
        -CheckId 'INT-007' `
        -Category 'Endpoint' `
        -Name 'Compliance — Automated Non-Compliance Actions' `
        -Status $int007Status `
        -Detail $int007Detail `
        -Recommendation "Configure automated actions for non-compliance in Intune: (1) Day 0: Send email to user, (2) Day 1: Mark device non-compliant, (3) Day 7: Retire device. This prevents persistent non-compliance without IT awareness." `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/actions-for-noncompliance' `
        -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
