#Requires -Version 7.0

<#
.SYNOPSIS
    Audits Microsoft Purview Data Loss Prevention (DLP) policies. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Exchange Online Management cmdlets instead of Graph API.

    WHY PS-ONLY:
    The Graph API DLP endpoint (/security/dataLossPreventionPolicies) lives in the
    beta namespace and has inconsistent property shapes depending on the workload.
    Get-DlpCompliancePolicy / Get-DlpComplianceRule are the AUTHORITATIVE source —
    they are the same cmdlets the Purview Compliance portal uses internally, and they
    expose reliable mode, workload location, and rule condition data.

    SEE ALSO (Graph variant):
        scripts/modules/DataProtection/Test-DLPPolicies.ps1

    Required connection:
        Connect-IPPSSession   (Exchange Online Protection / Compliance center)

    Required scopes / roles:
        Compliance Administrator  OR  View-Only DLP Compliance Management
        (These are Exchange Online RBAC roles, not Graph scopes.)

    Required modules:
        ExchangeOnlineManagement  (Install-Module ExchangeOnlineManagement)

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

    Note: Connect-IPPSSession must be called before invoking this function.
    The ExchangeOnlineManagement module provides both Connect-ExchangeOnline and
    Connect-IPPSSession — the latter targets the Security & Compliance endpoint.
#>

function Test-DLPPolicies {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve DLP policies via IPPS cmdlet (authoritative source)
    # -------------------------------------------------------------------------
    $dlpPolicies = $null
    try {
        $dlpPolicies = Get-DlpCompliancePolicy -All -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'DLP-000' `
            -Category 'DataProtection' `
            -Name 'DLP Policy Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: Connect-IPPSSession is required before running this module. Ensure you are connected to the Security & Compliance endpoint. Error: $_" `
            -Recommendation 'Run: Connect-IPPSSession. Then retry. Required role: Compliance Administrator or View-Only DLP Compliance Management.' `
            -Reference 'https://learn.microsoft.com/purview/dlp-learn-about-dlp' `
            -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # Retrieve DLP rules (for PII/condition checking in DLP-004)
    # -------------------------------------------------------------------------
    $dlpRules = $null
    try {
        $dlpRules = Get-DlpComplianceRule -All -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose "Could not retrieve DLP rules: $_"
        $dlpRules = @()
    }

    # -------------------------------------------------------------------------
    # DLP-001: DLP policies exist
    # -------------------------------------------------------------------------
    if ($dlpPolicies.Count -eq 0) {
        $results.Add((New-CheckResult `
            -CheckId 'DLP-001' `
            -Category 'DataProtection' `
            -Name 'DLP Policies Exist' `
            -Status 'HIGH' `
            -Detail 'No DLP policies found in the tenant. Sensitive data can be shared or exfiltrated without any automated detection or blocking.' `
            -Recommendation 'Create DLP policies to protect sensitive information types (PII, financial data, health records) across Exchange, SharePoint, OneDrive, and Teams.' `
            -Reference 'https://learn.microsoft.com/purview/dlp-learn-about-dlp' `
            -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $policyNames = $dlpPolicies | ForEach-Object { $_.Name } | Join-String -Separator ', '
    $results.Add((New-CheckResult `
        -CheckId 'DLP-001' `
        -Category 'DataProtection' `
        -Name 'DLP Policies Exist' `
        -Status 'PASS' `
        -Detail "$($dlpPolicies.Count) DLP policy/policies found: $policyNames." `
        -Recommendation 'Ensure DLP policies cover all critical workloads and are in enforcement mode.' `
        -Reference 'https://learn.microsoft.com/purview/dlp-learn-about-dlp' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # DLP-002: DLP coverage by workload
    # -------------------------------------------------------------------------
    # Get-DlpCompliancePolicy exposes Workload property directly
    $workloadMap = @{
        'Exchange'   = @('Exchange', 'All', 'ExchangeOnline')
        'SharePoint' = @('SharePoint', 'SharePointOnline', 'OneDriveForBusiness', 'All')
        'Teams'      = @('Teams', 'TeamsChat', 'MicrosoftTeams')
        'Endpoint'   = @('Devices', 'EndpointDevices', 'MicrosoftDefenderATP')
    }

    $coveredWorkloads   = [System.Collections.Generic.HashSet[string]]::new()
    $uncoveredWorkloads = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $dlpPolicies) {
        # Workload property is a multi-value string on DlpCompliancePolicy objects
        $workloadStr = $policy.Workload -as [string]
        foreach ($workload in $workloadMap.Keys) {
            foreach ($alias in $workloadMap[$workload]) {
                if ($workloadStr -match $alias) {
                    [void]$coveredWorkloads.Add($workload)
                }
            }
        }
    }

    $criticalWorkloads = @('Exchange', 'SharePoint', 'Teams')
    foreach ($workload in $criticalWorkloads) {
        if ($workload -notin $coveredWorkloads) {
            $uncoveredWorkloads.Add($workload)
        }
    }

    if ('Exchange' -notin $coveredWorkloads) {
        $dlp002Status = 'HIGH'
        $dlp002Detail = "Exchange is not covered by any DLP policy. Email is the primary exfiltration vector. Covered workloads: $($coveredWorkloads -join ', ')."
    }
    elseif ('Teams' -notin $coveredWorkloads) {
        $dlp002Status = 'MEDIUM'
        $dlp002Detail = "Teams chat is not covered by any DLP policy. Covered: $($coveredWorkloads -join ', '). Uncovered: $($uncoveredWorkloads -join ', ')."
    }
    elseif ($uncoveredWorkloads.Count -gt 0) {
        $dlp002Status = 'MEDIUM'
        $dlp002Detail = "Some workloads not covered: $($uncoveredWorkloads -join ', '). Covered: $($coveredWorkloads -join ', ')."
    }
    else {
        $dlp002Status = 'PASS'
        $dlp002Detail = "All critical workloads covered by DLP policies: $($coveredWorkloads -join ', ')."
    }

    $results.Add((New-CheckResult `
        -CheckId 'DLP-002' `
        -Category 'DataProtection' `
        -Name 'DLP Workload Coverage' `
        -Status $dlp002Status `
        -Detail $dlp002Detail `
        -Recommendation 'Ensure DLP policies cover Exchange Online, SharePoint/OneDrive, Teams, and Endpoint Devices. Each workload requires explicit policy assignment.' `
        -Reference 'https://learn.microsoft.com/purview/dlp-configure-endpoints-windows' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects $uncoveredWorkloads))

    # -------------------------------------------------------------------------
    # DLP-003: DLP policies in test mode vs enforcement
    # -------------------------------------------------------------------------
    # Get-DlpCompliancePolicy Mode property: Enable, TestWithNotifications, TestWithoutNotifications
    $testOnlyPolicies   = [System.Collections.Generic.List[string]]::new()
    $enforcedPolicies   = [System.Collections.Generic.List[string]]::new()
    $notifyOnlyPolicies = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $dlpPolicies) {
        $mode = $policy.Mode
        switch -Wildcard ($mode) {
            'TestWithoutNotifications' { $testOnlyPolicies.Add($policy.Name) }
            'TestWithNotifications'    { $notifyOnlyPolicies.Add($policy.Name) }
            'Enable'                   { $enforcedPolicies.Add($policy.Name) }
            'enforce'                  { $enforcedPolicies.Add($policy.Name) }
            default {
                Write-Verbose "Unknown DLP policy mode '$mode' for policy '$($policy.Name)'"
            }
        }
    }

    if ($enforcedPolicies.Count -eq 0) {
        $dlp003Status = 'HIGH'
        $dlp003Detail = "All $($dlpPolicies.Count) DLP policy/policies are in test mode — no enforcement active. Test-only: $($testOnlyPolicies -join ', '). Notify-only: $($notifyOnlyPolicies -join ', ')."
    }
    elseif ($testOnlyPolicies.Count -gt 0 -or $notifyOnlyPolicies.Count -gt 0) {
        $dlp003Status = 'MEDIUM'
        $dlp003Detail = "Mix of enforcement modes. Enforced: $($enforcedPolicies -join ', '). Test-only: $($testOnlyPolicies -join ', '). Notify-only: $($notifyOnlyPolicies -join ', ')."
    }
    else {
        $dlp003Status = 'PASS'
        $dlp003Detail = "All $($enforcedPolicies.Count) DLP policy/policies are in enforcement mode."
    }

    $results.Add((New-CheckResult `
        -CheckId 'DLP-003' `
        -Category 'DataProtection' `
        -Name 'DLP Policies in Enforcement Mode' `
        -Status $dlp003Status `
        -Detail $dlp003Detail `
        -Recommendation 'Move DLP policies from test mode to enforcement. Test mode only logs — it does not block or warn users. Review test mode results first, then enforce.' `
        -Reference 'https://learn.microsoft.com/purview/dlp-policy-design#start-with-test-mode' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects ($testOnlyPolicies + $notifyOnlyPolicies)))

    # -------------------------------------------------------------------------
    # DLP-004: DLP sensitive info types covered (PII focus)
    # Uses Get-DlpComplianceRule which has ContentContainsSensitiveInformation property
    # -------------------------------------------------------------------------
    $piiPatterns = @(
        'Credit Card', 'CreditCard',
        'Social Security', 'SSN',
        'Passport',
        'Medical', 'Health', 'HIPAA',
        'IBAN', 'Bank Account',
        'Driver', 'License'
    )

    $piiCoveredPolicies = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $dlpPolicies) {
        $policyRules = @($dlpRules | Where-Object { $_.ParentPolicyName -eq $policy.Name })
        foreach ($rule in $policyRules) {
            # ContentContainsSensitiveInformation is an array of SIT objects on the rule
            $sitJson = ($rule.ContentContainsSensitiveInformation | ConvertTo-Json -Depth 5 -Compress -ErrorAction SilentlyContinue) ?? ''
            $isPii = $piiPatterns | Where-Object { $sitJson -match $_ }
            if ($isPii) {
                $piiCoveredPolicies.Add($policy.Name)
                break
            }
        }
    }

    if ($piiCoveredPolicies.Count -eq 0) {
        $dlp004Status = 'MEDIUM'
        $dlp004Detail = 'No DLP policies found covering common PII sensitive information types (credit cards, SSN, passports, healthcare). Sensitive personal data may not be protected.'
    }
    else {
        $dlp004Status = 'PASS'
        $dlp004Detail = "PII-focused DLP policies found: $($piiCoveredPolicies | Sort-Object -Unique | Join-String -Separator ', ')."
    }

    $results.Add((New-CheckResult `
        -CheckId 'DLP-004' `
        -Category 'DataProtection' `
        -Name 'DLP PII Sensitive Info Types Covered' `
        -Status $dlp004Status `
        -Detail $dlp004Detail `
        -Recommendation 'Add DLP rules for: Credit Card Number, EU/US Social Security Number, Passport Numbers, IBAN, and health-related sensitive info types to cover GDPR and financial compliance.' `
        -Reference 'https://learn.microsoft.com/purview/sensitive-information-type-entity-definitions' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # DLP-005: DLP policy for Teams (sensitive information sharing in chat)
    # -------------------------------------------------------------------------
    $teamsWorkloadIds   = @('Teams', 'TeamsChat', 'MicrosoftTeams', 'TeamsChatMessages')
    $teamsDlpPolicies   = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $dlpPolicies) {
        $workloadStr = $policy.Workload -as [string]
        foreach ($alias in $teamsWorkloadIds) {
            if ($workloadStr -match $alias) {
                $teamsDlpPolicies.Add($policy.Name)
                break
            }
        }
    }

    $dlp005Status = if ($teamsDlpPolicies.Count -gt 0) { 'PASS' } else { 'MEDIUM' }
    $dlp005Detail = if ($teamsDlpPolicies.Count -gt 0) {
        "Teams is covered by $($teamsDlpPolicies.Count) DLP policy/policies: $($teamsDlpPolicies -join ', ')."
    }
    else {
        'No DLP policy covers Teams chat. Sensitive information shared in Teams channels and chats is not monitored or blocked.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'DLP-005' `
        -Category 'DataProtection' `
        -Name 'DLP Policy Covers Teams Chat' `
        -Status $dlp005Status `
        -Detail $dlp005Detail `
        -Recommendation 'Add Teams as a location in existing DLP policies or create a Teams-specific DLP policy to monitor and restrict sensitive information in chat and channel messages.' `
        -Reference 'https://learn.microsoft.com/purview/dlp-microsoft-teams' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    return $results
}
