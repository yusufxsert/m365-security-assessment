#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Intune device compliance policies and device compliance state.

.DESCRIPTION
    Test-IntuneCompliance evaluates the breadth and enforcement posture of Intune
    compliance policies across all managed device platforms. It checks policy
    existence per OS, grace periods, enforcement actions, non-compliant device
    counts, platform coverage, and BitLocker/encryption requirements.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        DeviceManagementConfiguration.Read.All
        DeviceManagementManagedDevices.Read.All

    License Required: E3 minimum (Intune)
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/Endpoint/Test-IntuneCompliance.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-IntuneCompliance {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all compliance policies
    # -------------------------------------------------------------------------
    $compliancePolicies = $null
    try {
        $uri = 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$top=100'
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $compliancePolicies = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $response.value) { $compliancePolicies.Add($item) }
        $nextLink = $response.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($item in $page.value) { $compliancePolicies.Add($item) }
            $nextLink = $page.'@odata.nextLink'
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'INT-000' `
            -Category 'Endpoint' `
            -Name 'Intune Compliance Policy Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: DeviceManagementConfiguration.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementConfiguration.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # INT-001: Compliance policies exist per platform
    # -------------------------------------------------------------------------
    $requiredPlatforms = @('windows10CompliancePolicy', 'iosCompliancePolicy', 'androidCompliancePolicy')
    $platformDisplayNames = @{
        'windows10CompliancePolicy'   = 'Windows'
        'iosCompliancePolicy'         = 'iOS'
        'androidCompliancePolicy'     = 'Android'
        'macOSCompliancePolicy'       = 'macOS'
        'androidWorkProfileCompliance' = 'Android Work Profile'
    }

    $coveredOdataTypes = @($compliancePolicies | ForEach-Object { $_.'@odata.type' -replace '#microsoft.graph.', '' } | Sort-Object -Unique)
    $coveredDisplayed  = @($coveredOdataTypes | ForEach-Object { if ($platformDisplayNames[$_]) { $platformDisplayNames[$_] } else { $_ } })
    $missingRequired   = @($requiredPlatforms | Where-Object { $_ -notin $coveredOdataTypes })
    $missingDisplayed  = @($missingRequired   | ForEach-Object { $platformDisplayNames[$_] })

    if ($compliancePolicies.Count -eq 0) {
        $int001Status = 'HIGH'
        $int001Detail = 'No compliance policies found in the tenant. All devices will be marked compliant by default (no enforcement).'
    }
    elseif ($missingRequired.Count -gt 0) {
        $int001Status = 'HIGH'
        $int001Detail = "Compliance policies present for: $($coveredDisplayed -join ', '). Missing required platforms: $($missingDisplayed -join ', ')."
    }
    else {
        $int001Status = 'PASS'
        $int001Detail = "Compliance policies present for: $($coveredDisplayed -join ', ')."
    }

    $results.Add((New-CheckResult `
        -CheckId 'INT-001' `
        -Category 'Endpoint' `
        -Name 'Compliance Policies Exist Per Platform' `
        -Status $int001Status `
        -Detail $int001Detail `
        -Recommendation 'Create compliance policies for Windows, iOS, and Android at minimum. Without a policy, devices default to compliant.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
        -CISControl 'CIS 5.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects $missingDisplayed))

    # -------------------------------------------------------------------------
    # INT-002: Non-compliant device count and percentage
    # -------------------------------------------------------------------------
    try {
        $nonCompliantUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=complianceState eq 'noncompliant'&`$select=id,deviceName,operatingSystem,complianceState&`$top=100"
        $ncResponse = Invoke-MgGraphRequest -Method GET -Uri $nonCompliantUri -ErrorAction Stop
        $nonCompliantDevices = [System.Collections.Generic.List[object]]::new()
        foreach ($d in $ncResponse.value) { $nonCompliantDevices.Add($d) }
        $ncNextLink = $ncResponse.'@odata.nextLink'
        while ($ncNextLink) {
            $ncPage = Invoke-MgGraphRequest -Method GET -Uri $ncNextLink -ErrorAction Stop
            foreach ($d in $ncPage.value) { $nonCompliantDevices.Add($d) }
            $ncNextLink = $ncPage.'@odata.nextLink'
        }

        $totalUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id&`$top=1"
        $totalResp = Invoke-MgGraphRequest -Method GET -Uri $totalUri -ErrorAction Stop
        # Count via $count header
        $totalCountUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/`$count"
        try {
            $totalCountResp = Invoke-MgGraphRequest -Method GET -Uri $totalCountUri `
                -Headers @{'ConsistencyLevel' = 'eventual'} -ErrorAction Stop
            $totalDevices = [int]$totalCountResp
        }
        catch {
            # Fallback: fetch all and count
            $allDevUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id&`$top=999"
            $allDevResp = Invoke-MgGraphRequest -Method GET -Uri $allDevUri -ErrorAction Stop
            $totalDevices = $allDevResp.value.Count
        }

        $ncCount   = $nonCompliantDevices.Count
        $ncPct     = if ($totalDevices -gt 0) { [math]::Round(($ncCount / $totalDevices) * 100, 1) } else { 0 }
        $ncSample  = @($nonCompliantDevices | Select-Object -First 20 | ForEach-Object { "$($_.deviceName) [$($_.operatingSystem)]" })

        if ($ncPct -gt 30) {
            $int002Status = 'CRITICAL'
        }
        elseif ($ncPct -gt 10) {
            $int002Status = 'HIGH'
        }
        else {
            $int002Status = 'PASS'
        }

        $results.Add((New-CheckResult `
            -CheckId 'INT-002' `
            -Category 'Endpoint' `
            -Name 'Non-Compliant Device Count' `
            -Status $int002Status `
            -Detail "$ncCount of $totalDevices managed devices are non-compliant ($ncPct%)." `
            -Recommendation 'Investigate non-compliant devices. Ensure Conditional Access blocks non-compliant devices from corporate resources. Review compliance policy requirements.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -CISControl 'CIS 5.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects $ncSample))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'INT-002' `
            -Category 'Endpoint' `
            -Name 'Non-Compliant Device Count' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: DeviceManagementManagedDevices.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementManagedDevices.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -CISControl 'CIS 5.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # INT-003: Compliance grace period settings
    # -------------------------------------------------------------------------
    $longGracePolicies   = [System.Collections.Generic.List[string]]::new()  # > 14 days
    $mediumGracePolicies = [System.Collections.Generic.List[string]]::new()  # > 7 days

    foreach ($policy in $compliancePolicies) {
        $grace = $policy.nonComplianceGracePeriodInDays
        if ($null -ne $grace -and $grace -gt 14) {
            $longGracePolicies.Add("$($policy.displayName) ($grace days)")
        }
        elseif ($null -ne $grace -and $grace -gt 7) {
            $mediumGracePolicies.Add("$($policy.displayName) ($grace days)")
        }
    }

    if ($longGracePolicies.Count -gt 0) {
        $int003Status = 'HIGH'
        $int003Detail = "Policies with grace period > 14 days: $($longGracePolicies -join '; ')."
        if ($mediumGracePolicies.Count -gt 0) {
            $int003Detail += " Policies with grace period 8-14 days: $($mediumGracePolicies -join '; ')."
        }
    }
    elseif ($mediumGracePolicies.Count -gt 0) {
        $int003Status = 'MEDIUM'
        $int003Detail = "Policies with grace period > 7 days: $($mediumGracePolicies -join '; ')."
    }
    else {
        $int003Status = 'PASS'
        $int003Detail = 'No compliance policies have grace periods exceeding 7 days.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'INT-003' `
        -Category 'Endpoint' `
        -Name 'Compliance Grace Period Settings' `
        -Status $int003Status `
        -Detail $int003Detail `
        -Recommendation 'Set grace periods to 0-7 days. Long grace periods delay enforcement and allow non-compliant devices continued access.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started#compliance-policy-settings' `
        -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects ($longGracePolicies + $mediumGracePolicies)))

    # -------------------------------------------------------------------------
    # INT-004: Compliance policy actions (enforcement on non-compliance)
    # -------------------------------------------------------------------------
    $noActionPolicies     = [System.Collections.Generic.List[string]]::new()
    $retireActionPolicies = [System.Collections.Generic.List[string]]::new()
    $notifyActionPolicies = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $compliancePolicies) {
        $actions = @($policy.scheduledActionsForRule)
        if ($null -eq $actions -or $actions.Count -eq 0) {
            $noActionPolicies.Add($policy.displayName)
            continue
        }

        $allActionTypes = @($actions | ForEach-Object { $_.scheduledActionConfigurations } | ForEach-Object { $_.actionType })
        if ('retire' -in $allActionTypes -or 'wipe' -in $allActionTypes) {
            $retireActionPolicies.Add($policy.displayName)
        }
        if ('notification' -in $allActionTypes -or 'pushNotification' -in $allActionTypes) {
            $notifyActionPolicies.Add($policy.displayName)
        }
        if ($allActionTypes.Count -eq 0 -or ($allActionTypes | Where-Object { $_ -ne 'block' }).Count -eq 0) {
            $noActionPolicies.Add($policy.displayName)
        }
    }

    if ($noActionPolicies.Count -gt 0) {
        $int004Status = 'HIGH'
        $int004Detail = "Policies with no enforcement action configured (mark non-compliant only): $($noActionPolicies -join '; ')."
    }
    else {
        $int004Status = 'PASS'
        $int004Detail = 'All compliance policies have enforcement actions configured.'
    }
    if ($retireActionPolicies.Count -gt 0) {
        $int004Detail += " Policies with retire/wipe action: $($retireActionPolicies -join '; ')."
    }
    if ($notifyActionPolicies.Count -gt 0) {
        $int004Detail += " Policies with notification action: $($notifyActionPolicies -join '; ')."
    }

    $results.Add((New-CheckResult `
        -CheckId 'INT-004' `
        -Category 'Endpoint' `
        -Name 'Compliance Policy Enforcement Actions' `
        -Status $int004Status `
        -Detail $int004Detail `
        -Recommendation 'Configure at minimum a notification action for non-compliance. Consider retire/wipe for corporate-owned devices after extended non-compliance.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started#actions-for-noncompliance' `
        -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects ($noActionPolicies | Select-Object -First 20)))

    # -------------------------------------------------------------------------
    # INT-005: Devices without compliance policy assignment (unknown/notApplicable)
    # -------------------------------------------------------------------------
    try {
        $unknownUri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=complianceState eq 'unknown' or complianceState eq 'notApplicable'&`$select=id,deviceName,operatingSystem,complianceState&`$top=100"
        $ukResponse = Invoke-MgGraphRequest -Method GET -Uri $unknownUri -ErrorAction Stop
        $unknownDevices = [System.Collections.Generic.List[object]]::new()
        foreach ($d in $ukResponse.value) { $unknownDevices.Add($d) }
        $ukNextLink = $ukResponse.'@odata.nextLink'
        while ($ukNextLink) {
            $ukPage = Invoke-MgGraphRequest -Method GET -Uri $ukNextLink -ErrorAction Stop
            foreach ($d in $ukPage.value) { $unknownDevices.Add($d) }
            $ukNextLink = $ukPage.'@odata.nextLink'
        }

        $ukCount = $unknownDevices.Count
        $totalCountUri2 = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/`$count"
        try {
            $totalDev2 = [int](Invoke-MgGraphRequest -Method GET -Uri $totalCountUri2 `
                -Headers @{'ConsistencyLevel' = 'eventual'} -ErrorAction Stop)
        }
        catch {
            $totalDev2 = $ukCount + 1  # avoid divide-by-zero; show raw count
        }

        $ukPct = if ($totalDev2 -gt 0) { [math]::Round(($ukCount / $totalDev2) * 100, 1) } else { 0 }
        $ukSample = @($unknownDevices | Select-Object -First 20 | ForEach-Object { "$($_.deviceName) [$($_.complianceState)]" })

        $int005Status = if ($ukPct -gt 5) { 'MEDIUM' } else { 'PASS' }

        $results.Add((New-CheckResult `
            -CheckId 'INT-005' `
            -Category 'Endpoint' `
            -Name 'Devices Without Compliance Policy Assignment' `
            -Status $int005Status `
            -Detail "$ukCount devices have unknown or not-applicable compliance state ($ukPct% of total). These devices are not evaluated by any compliance policy." `
            -Recommendation 'Assign compliance policies to all device groups. Devices without an assigned policy default to compliant, bypassing enforcement.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects $ukSample))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'INT-005' `
            -Category 'Endpoint' `
            -Name 'Devices Without Compliance Policy Assignment' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: DeviceManagementManagedDevices.Read.All. Error: $_" `
            -Recommendation 'Grant DeviceManagementManagedDevices.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
            -CISControl '' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # INT-006: Compliance policy for each OS platform
    # -------------------------------------------------------------------------
    $allRequiredPlatforms = @('windows10CompliancePolicy', 'iosCompliancePolicy', 'macOSCompliancePolicy', 'androidCompliancePolicy')
    $allPlatformNames = @{
        'windows10CompliancePolicy' = 'Windows'
        'iosCompliancePolicy'       = 'iOS'
        'macOSCompliancePolicy'     = 'macOS'
        'androidCompliancePolicy'   = 'Android'
    }
    $missingAll = @($allRequiredPlatforms | Where-Object { $_ -notin $coveredOdataTypes })
    $missingAllNames = @($missingAll | ForEach-Object { $allPlatformNames[$_] })

    $int006Status = if ($missingAll.Count -eq 0) { 'PASS' } else { 'MEDIUM' }
    $int006Detail = if ($missingAll.Count -eq 0) {
        "Compliance policies exist for all four platforms: Windows, iOS, macOS, Android."
    }
    else {
        "Missing compliance policies for: $($missingAllNames -join ', '). Present for: $($coveredDisplayed -join ', ')."
    }

    $results.Add((New-CheckResult `
        -CheckId 'INT-006' `
        -Category 'Endpoint' `
        -Name 'Compliance Policy Per OS Platform' `
        -Status $int006Status `
        -Detail $int006Detail `
        -Recommendation 'Create compliance policies for Windows, iOS, macOS, and Android to ensure all platforms are evaluated.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/device-compliance-get-started' `
        -CISControl 'CIS 5.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects $missingAllNames))

    # -------------------------------------------------------------------------
    # INT-007: BitLocker/FileVault/Device Encryption in compliance policy
    # -------------------------------------------------------------------------
    $windowsPolicies = @($compliancePolicies | Where-Object {
        $_.'@odata.type' -match 'windows10CompliancePolicy'
    })

    $bitlockerEnforced = @($windowsPolicies | Where-Object {
        $_.storageRequireEncryption -eq $true
    })

    if ($windowsPolicies.Count -eq 0) {
        $int007Status = 'HIGH'
        $int007Detail = 'No Windows compliance policy found — BitLocker requirement cannot be evaluated.'
    }
    elseif ($bitlockerEnforced.Count -eq 0) {
        $int007Status = 'HIGH'
        $int007Detail = "Found $($windowsPolicies.Count) Windows compliance policy/policies, but none require BitLocker (storageRequireEncryption = false)."
    }
    else {
        $int007Status = 'PASS'
        $int007Detail = "$($bitlockerEnforced.Count) of $($windowsPolicies.Count) Windows compliance policy/policies require BitLocker encryption."
    }

    $results.Add((New-CheckResult `
        -CheckId 'INT-007' `
        -Category 'Endpoint' `
        -Name 'BitLocker Required in Windows Compliance Policy' `
        -Status $int007Status `
        -Detail $int007Detail `
        -Recommendation 'Enable storageRequireEncryption in all Windows compliance policies. This ensures unencrypted devices are flagged as non-compliant.' `
        -Reference 'https://learn.microsoft.com/mem/intune/protect/compliance-policy-create-windows' `
        -CISControl 'CIS 5.1' -SC300Domain 'Device Management' -LicenseRequired 'E3' `
        -AffectedObjects @($windowsPolicies | Where-Object { $_.storageRequireEncryption -ne $true } | ForEach-Object { $_.displayName })))

    return $results
}
