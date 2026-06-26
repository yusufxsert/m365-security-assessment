#Requires -Version 7.0

<#
.SYNOPSIS
    Audits Microsoft Purview Sensitivity Labels configuration and publishing. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-Label and Get-LabelPolicy (IPPS cmdlets) instead of
    the Graph Security API sensitivity labels endpoints.

    WHY PS-ONLY:
    Get-Label / Get-LabelPolicy are AUTHORITATIVE — they are the same cmdlets the
    Purview Compliance portal uses and expose complete label configuration including:
    - Encryption settings (EncryptionEnabled, EncryptionRightsDefinitions)
    - Content marking (HeaderText, FooterText, WaterMarkText)
    - Auto-labeling conditions
    - Policy scope (users/groups targeted by each label policy)

    The Graph beta endpoint /security/informationProtection/sensitivityLabels
    mirrors these objects but can lag and has inconsistent property exposure.

    SEE ALSO (Graph variant):
        scripts/modules/DataProtection/Test-SensitivityLabels.ps1

    Required connection:
        Connect-IPPSSession   (Security & Compliance endpoint)

    Required roles (Exchange RBAC):
        Sensitivity Label Administrator  OR  View-Only Record Management

    Required modules:
        ExchangeOnlineManagement  (Install-Module ExchangeOnlineManagement)

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-SensitivityLabels {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve sensitivity labels via IPPS (authoritative)
    # -------------------------------------------------------------------------
    $labels = $null
    try {
        $labels = Get-Label -IncludeDetailedLabelActions $true -ErrorAction Stop
    }
    catch {
        # Try without IncludeDetailedLabelActions (older module version)
        try {
            $labels = Get-Label -ErrorAction Stop
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'SLB-000' `
                -Category 'DataProtection' `
                -Name 'Sensitivity Labels Retrieval' `
                -Status 'INFO' `
                -Detail "Check skipped: Connect-IPPSSession is required. Ensure the account has Sensitivity Label Administrator or View-Only Record Management role. Error: $_" `
                -Recommendation 'Run: Connect-IPPSSession. Required role: Sensitivity Label Administrator.' `
                -Reference 'https://learn.microsoft.com/purview/sensitivity-labels' `
                -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
                -AffectedObjects @()))
            return $results
        }
    }

    # -------------------------------------------------------------------------
    # SLB-001: Sensitivity labels created and published
    # -------------------------------------------------------------------------
    if ($labels.Count -eq 0) {
        $slb001Status = 'HIGH'
        $slb001Detail = 'No sensitivity labels found. Purview Information Protection labeling is not configured.'
    }
    else {
        $labelNames   = ($labels | ForEach-Object { $_.DisplayName ?? $_.Name }) -join ', '
        $slb001Status = 'PASS'
        $slb001Detail = "$($labels.Count) sensitivity label(s) found: $labelNames."
    }

    $results.Add((New-CheckResult `
        -CheckId 'SLB-001' `
        -Category 'DataProtection' `
        -Name 'Sensitivity Labels Created and Published' `
        -Status $slb001Status `
        -Detail $slb001Detail `
        -Recommendation 'Create and publish at least a basic sensitivity label taxonomy: Public, Internal, Confidential, Highly Confidential. Labels must be published via a label policy to be visible to users.' `
        -Reference 'https://learn.microsoft.com/purview/sensitivity-labels#what-sensitivity-labels-can-do' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    if ($labels.Count -eq 0) { return $results }

    # -------------------------------------------------------------------------
    # Retrieve label policies via IPPS (authoritative)
    # -------------------------------------------------------------------------
    $labelPolicies = $null
    try {
        $labelPolicies = Get-LabelPolicy -ErrorAction Stop
    }
    catch {
        Write-Verbose "Could not retrieve label policies: $_"
        $labelPolicies = @()
    }

    # -------------------------------------------------------------------------
    # SLB-002: Labels published to all users (not just pilot group)
    # -------------------------------------------------------------------------
    if ($null -eq $labelPolicies -or $labelPolicies.Count -eq 0) {
        $slb002Status = 'MEDIUM'
        $slb002Detail = 'No label publishing policies found. Labels cannot be used by end users until a label policy is created and published.'
    }
    else {
        # On Get-LabelPolicy objects, ModernGroupLocation / ExchangeLocation / etc. being empty
        # usually means the policy applies to all. ExchangeLocation with 'All' means all users.
        $allUserPolicies = @($labelPolicies | Where-Object {
            ($null -eq $_.ExchangeLocation -or $_.ExchangeLocation.Count -eq 0) -or
            ($_.ExchangeLocation | Where-Object { $_.Name -eq 'All' })
        })

        if ($allUserPolicies.Count -gt 0) {
            $slb002Status = 'PASS'
            $slb002Detail = "$($allUserPolicies.Count) label policy/policies published to all users (no scope restriction)."
        }
        else {
            $slb002Status = 'MEDIUM'
            $slb002Detail = "All $($labelPolicies.Count) label policy/policies appear to be scoped to specific groups. Users outside these groups will not see sensitivity labels."
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'SLB-002' `
        -Category 'DataProtection' `
        -Name 'Labels Published to All Users' `
        -Status $slb002Status `
        -Detail $slb002Detail `
        -Recommendation 'Publish sensitivity labels to all users via a label policy scoped to all users or all licensed users. Pilot groups are fine during initial rollout but should not remain permanent.' `
        -Reference 'https://learn.microsoft.com/purview/create-sensitivity-labels#publish-sensitivity-labels-by-creating-a-label-policy' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SLB-003: Auto-labeling policies configured (E5 feature)
    # Get-AutoSensitivityLabelPolicy is the IPPS cmdlet for auto-labeling policies
    # -------------------------------------------------------------------------
    try {
        $autoLabelPolicies = Get-AutoSensitivityLabelPolicy -ErrorAction Stop
        if ($autoLabelPolicies.Count -eq 0) {
            $slb003Status = 'LOW'
            $slb003Detail = 'No auto-labeling policies found. Labels are applied manually only — unreliable for sensitive data classification at scale.'
        }
        else {
            $slb003Status = 'PASS'
            $slb003Detail = "$($autoLabelPolicies.Count) auto-labeling policy/policies configured: $($autoLabelPolicies | ForEach-Object { $_.Name } | Join-String -Separator ', ')."
        }
    }
    catch {
        $slb003Status = 'LOW'
        $slb003Detail = "Auto-labeling policies could not be retrieved. Get-AutoSensitivityLabelPolicy may require E5 license or Sensitivity Label Administrator role. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'SLB-003' `
        -Category 'DataProtection' `
        -Name 'Auto-Labeling Policies Configured' `
        -Status $slb003Status `
        -Detail $slb003Detail `
        -Recommendation 'Configure auto-labeling policies for SharePoint, OneDrive, and Exchange to automatically classify documents containing sensitive information types (e.g. credit cards, PII).' `
        -Reference 'https://learn.microsoft.com/purview/apply-sensitivity-label-automatically' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SLB-004: Mandatory labeling policy
    # On Get-LabelPolicy, Settings property contains mandatory labeling config
    # -------------------------------------------------------------------------
    $mandatoryLabelingEnabled = $false
    if ($labelPolicies -and $labelPolicies.Count -gt 0) {
        foreach ($policy in $labelPolicies) {
            # Settings hashtable on DlpLabelPolicy: MandatoryLabel = True
            $settings = $policy.Settings
            if ($settings -and ($settings -match 'mandatory' -or $settings -match 'requiredowngrade')) {
                $mandatoryLabelingEnabled = $true
                break
            }
            # Also check RequiredLabel / MandatoryLabel as direct properties
            if ($policy.MandatoryLabel -eq $true -or $policy.RequireMandatoryLabel -eq $true) {
                $mandatoryLabelingEnabled = $true
                break
            }
        }
    }

    $slb004Status = if ($mandatoryLabelingEnabled) { 'PASS' } else { 'MEDIUM' }
    $slb004Detail = if ($mandatoryLabelingEnabled) {
        'Mandatory labeling is configured — users must apply a label before saving/sending documents or emails.'
    }
    else {
        'Mandatory labeling policy not detected. Labeling appears optional, which leads to inconsistent classification and unprotected sensitive data.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'SLB-004' `
        -Category 'DataProtection' `
        -Name 'Mandatory Labeling Policy Enforced' `
        -Status $slb004Status `
        -Detail $slb004Detail `
        -Recommendation 'Enable mandatory labeling in label policies so users cannot save Office files or send emails without applying a sensitivity label.' `
        -Reference 'https://learn.microsoft.com/purview/sensitivity-labels-office-apps#require-users-to-apply-a-label-to-their-email-or-documents' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # SLB-005: Encryption configured for confidential labels
    # Get-Label with -IncludeDetailedLabelActions exposes EncryptionEnabled property
    # -------------------------------------------------------------------------
    $confidentialLabels = @($labels | Where-Object {
        ($_.DisplayName ?? $_.Name) -match 'Confidential|Highly Confidential|Restricted|Secret'
    })

    if ($confidentialLabels.Count -eq 0) {
        $slb005Status = 'MEDIUM'
        $slb005Detail = 'No labels with "Confidential" or "Highly Confidential" naming found. Cannot verify encryption requirement for sensitive labels.'
        $labelsWithoutEncryption = @()
    }
    else {
        $labelsWithoutEncryption = [System.Collections.Generic.List[string]]::new()
        foreach ($label in $confidentialLabels) {
            $labelName = $label.DisplayName ?? $label.Name
            # EncryptionEnabled is a boolean on the IPPS label object
            if ($label.EncryptionEnabled -ne $true) {
                $labelsWithoutEncryption.Add($labelName)
            }
        }

        if ($labelsWithoutEncryption.Count -gt 0) {
            $slb005Status = 'HIGH'
            $slb005Detail = "Confidential labels without encryption enabled: $($labelsWithoutEncryption -join ', '). Sensitive content may not be protected even when labeled."
        }
        else {
            $slb005Status = 'PASS'
            $slb005Detail = "$($confidentialLabels.Count) confidential label(s) all have EncryptionEnabled = True."
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'SLB-005' `
        -Category 'DataProtection' `
        -Name 'Encryption Configured for Confidential Labels' `
        -Status $slb005Status `
        -Detail $slb005Detail `
        -Recommendation 'Configure encryption on Confidential and Highly Confidential labels. Use Rights Management to restrict access and enable document tracking.' `
        -Reference 'https://learn.microsoft.com/purview/encryption-sensitivity-labels' `
        -CISControl '' -SC300Domain 'Information Protection' -LicenseRequired 'E5' `
        -AffectedObjects ($labelsWithoutEncryption ?? @())))

    return $results
}
