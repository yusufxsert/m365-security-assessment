#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Microsoft Purview Data Loss Prevention (DLP) policies.

.DESCRIPTION
    Test-DLPPolicies evaluates whether DLP policies exist, which workloads
    are covered (Exchange, SharePoint, Teams, Endpoint), whether policies are
    in test/enforce mode, whether PII-focused sensitive information types are
    included, and whether Teams chat is explicitly covered.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        DataLossPreventionPolicy.Read.All  (requires E3 Compliance add-on or M365 E3/E5)

    License Required: E3 minimum with Compliance add-on
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.

    Note: DLP policies are managed via the Compliance Center / Purview. The
    Graph Security API provides read access. Policy details may be limited
    based on available permissions.
#>

function Test-DLPPolicies {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve DLP policies via compliance endpoint
    # -------------------------------------------------------------------------
    $dlpPolicies = $null
    try {
        $dlpUri = 'https://graph.microsoft.com/v1.0/security/dataLossPreventionPolicies?$top=100'
        $dlpResp = Invoke-MgGraphRequest -Method GET -Uri $dlpUri -ErrorAction Stop
        $dlpPolicies = [System.Collections.Generic.List[object]]::new()
        foreach ($p in $dlpResp.value) { $dlpPolicies.Add($p) }
        $nextLink = $dlpResp.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($p in $page.value) { $dlpPolicies.Add($p) }
            $nextLink = $page.'@odata.nextLink'
        }
    }
    catch {
        # Fallback: try beta endpoint
        try {
            $betaDlpUri = 'https://graph.microsoft.com/beta/security/dataLossPreventionPolicies?$top=100'
            $betaDlpResp = Invoke-MgGraphRequest -Method GET -Uri $betaDlpUri -ErrorAction Stop
            $dlpPolicies = [System.Collections.Generic.List[object]]::new()
            foreach ($p in $betaDlpResp.value) { $dlpPolicies.Add($p) }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'DLP-000' `
                -Category 'DataProtection' `
                -Name 'DLP Policy Retrieval' `
                -Status 'INFO' `
                -Detail "Check skipped: insufficient permissions or Purview Compliance not available. Required: DataLossPreventionPolicy.Read.All. Error: $_" `
                -Recommendation 'Grant DataLossPreventionPolicy.Read.All to the service principal. Verify the tenant has a Compliance license.' `
                -Reference 'https://learn.microsoft.com/purview/dlp-learn-about-dlp' `
                -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
                -AffectedObjects @()))
            return $results
        }
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

    $results.Add((New-CheckResult `
        -CheckId 'DLP-001' `
        -Category 'DataProtection' `
        -Name 'DLP Policies Exist' `
        -Status 'PASS' `
        -Detail "$($dlpPolicies.Count) DLP policy/policies found: $($dlpPolicies | ForEach-Object { $_.name ?? $_.displayName } | Join-String -Separator ', ')." `
        -Recommendation 'Ensure DLP policies cover all critical workloads and are in enforcement mode.' `
        -Reference 'https://learn.microsoft.com/purview/dlp-learn-about-dlp' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # DLP-002: DLP coverage by workload
    # -------------------------------------------------------------------------
    # Workload location identifiers used by Purview DLP policies
    $workloadMap = @{
        'Exchange'   = @('Exchange', 'All', 'ExchangeOnline')
        'SharePoint' = @('SharePoint', 'SharePointOnline', 'OneDriveForBusiness', 'All')
        'Teams'      = @('Teams', 'TeamsChat', 'MicrosoftTeams')
        'Endpoint'   = @('Devices', 'EndpointDevices', 'MicrosoftDefenderATP')
    }

    $coveredWorkloads    = [System.Collections.Generic.HashSet[string]]::new()
    $uncoveredWorkloads  = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $dlpPolicies) {
        $locations = @($policy.locations ?? $policy.policyDetails.locations)
        foreach ($loc in $locations) {
            $locName = $loc.name ?? $loc.location ?? $loc
            foreach ($workload in $workloadMap.Keys) {
                if ($workloadMap[$workload] | Where-Object { $locName -match $_ }) {
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
    $testOnlyPolicies   = [System.Collections.Generic.List[string]]::new()
    $enforcedPolicies   = [System.Collections.Generic.List[string]]::new()
    $notifyOnlyPolicies = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $dlpPolicies) {
        $mode = $policy.mode ?? $policy.policyMode
        $policyName = $policy.name ?? $policy.displayName
        switch -Wildcard ($mode) {
            'testWithoutNotifications' { $testOnlyPolicies.Add($policyName) }
            'testWithNotifications'    { $notifyOnlyPolicies.Add($policyName) }
            'enforce'                  { $enforcedPolicies.Add($policyName) }
            'Enable'                   { $enforcedPolicies.Add($policyName) }
            default {
                # Unknown/null mode — assume not enforced
                Write-Verbose "Unknown DLP policy mode '$mode' for policy '$policyName'"
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
        $policyName = $policy.name ?? $policy.displayName
        $rules = @($policy.rules ?? $policy.policyDetails.rules)
        foreach ($rule in $rules) {
            $conditionJson = ($rule | ConvertTo-Json -Depth 10 -Compress)
            $isPii = $piiPatterns | Where-Object { $conditionJson -match $_ }
            if ($isPii) {
                $piiCoveredPolicies.Add($policyName)
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
    $teamsWorkloadIds = @('Teams', 'TeamsChat', 'MicrosoftTeams', 'TeamsChatMessages')
    $teamsDlpPolicies = [System.Collections.Generic.List[string]]::new()

    foreach ($policy in $dlpPolicies) {
        $policyName = $policy.name ?? $policy.displayName
        $locations = @($policy.locations ?? $policy.policyDetails.locations)
        foreach ($loc in $locations) {
            $locName = $loc.name ?? $loc.location ?? $loc
            if ($teamsWorkloadIds | Where-Object { $locName -match $_ }) {
                $teamsDlpPolicies.Add($policyName)
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
