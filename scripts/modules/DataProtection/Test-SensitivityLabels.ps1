#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Microsoft Purview Sensitivity Labels configuration and publishing.

.DESCRIPTION
    Test-SensitivityLabels evaluates whether sensitivity labels exist, are published
    to all users, include auto-labeling policies, enforce mandatory labeling, and
    whether confidential/highly-confidential labels apply encryption.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        InformationProtectionPolicy.Read.All

    License Required:
        SLB-001 through SLB-004: E3 (basic labeling)
        SLB-003 auto-labeling, SLB-005 encryption: E5 / M365 E5 Compliance

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.

    Note: The Sensitivity Labels Graph API endpoint requires Purview/MIP to be
    configured in the tenant. The beta endpoint is used for label policies.
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/DataProtection/Test-SensitivityLabels.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-SensitivityLabels {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve sensitivity labels
    # -------------------------------------------------------------------------
    $labels = $null
    try {
        # v1.0 endpoint for sensitivity labels
        $labelsUri = 'https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels?$top=100'
        $labelsResp = Invoke-MgGraphRequest -Method GET -Uri $labelsUri -ErrorAction Stop
        $labels = [System.Collections.Generic.List[object]]::new()
        foreach ($l in $labelsResp.value) { $labels.Add($l) }
        $nextLink = $labelsResp.'@odata.nextLink'
        while ($nextLink) {
            $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            foreach ($l in $page.value) { $labels.Add($l) }
            $nextLink = $page.'@odata.nextLink'
        }
    }
    catch {
        # Fallback: try beta endpoint
        try {
            $betaUri = 'https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels?$top=100'
            $betaResp = Invoke-MgGraphRequest -Method GET -Uri $betaUri -ErrorAction Stop
            $labels = [System.Collections.Generic.List[object]]::new()
            foreach ($l in $betaResp.value) { $labels.Add($l) }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'SLB-000' `
                -Category 'DataProtection' `
                -Name 'Sensitivity Labels Retrieval' `
                -Status 'INFO' `
                -Detail "Check skipped: insufficient permissions or Purview not configured. Required: InformationProtectionPolicy.Read.All. Error: $_" `
                -Recommendation 'Grant InformationProtectionPolicy.Read.All to the service principal and verify Microsoft Purview is activated.' `
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
        $slb001Status = 'PASS'
        $slb001Detail = "$($labels.Count) sensitivity label(s) found: $($labels | ForEach-Object { $_.name } | Join-String -Separator ', ')."
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
    # Retrieve label policies (beta endpoint)
    # -------------------------------------------------------------------------
    $labelPolicies = $null
    try {
        $policiesUri = 'https://graph.microsoft.com/beta/informationProtection/policy/labels?$top=100'
        $policiesResp = Invoke-MgGraphRequest -Method GET -Uri $policiesUri -ErrorAction Stop
        $labelPolicies = $policiesResp.value
    }
    catch {
        Write-Verbose "Could not retrieve label policies via beta endpoint: $_"
        $labelPolicies = @()
    }

    # -------------------------------------------------------------------------
    # SLB-002: Labels published to all users (not just pilot group)
    # -------------------------------------------------------------------------
    if ($null -eq $labelPolicies -or $labelPolicies.Count -eq 0) {
        $slb002Status = 'MEDIUM'
        $slb002Detail = 'Could not retrieve label publishing policies. Verify that labels are published to all users, not just a pilot group.'
    }
    else {
        # Check if any policy targets 'all' users (no specific group assignment)
        $allUserPolicies = @($labelPolicies | Where-Object {
            $null -eq $_.assignedTo -or $_.assignedTo.Count -eq 0
        })

        if ($allUserPolicies.Count -gt 0) {
            $slb002Status = 'PASS'
            $slb002Detail = "$($allUserPolicies.Count) label policy/policies published to all users."
        }
        else {
            $slb002Status = 'MEDIUM'
            $slb002Detail = "All $($labelPolicies.Count) label policy/policies are scoped to specific groups. Users outside these groups will not see sensitivity labels."
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
    # -------------------------------------------------------------------------
    try {
        $autoLabelUri = 'https://graph.microsoft.com/beta/security/informationProtection/labelPolicies?$top=50'
        $autoLabelResp = Invoke-MgGraphRequest -Method GET -Uri $autoLabelUri -ErrorAction Stop
        $autoLabelPolicies = @($autoLabelResp.value | Where-Object {
            $_.autoLabeling -ne $null -or $_.mode -eq 'autoApply'
        })

        if ($autoLabelPolicies.Count -eq 0) {
            $slb003Status = 'LOW'
            $slb003Detail = 'No auto-labeling policies found. Labels are applied manually only — unreliable for sensitive data classification at scale.'
        }
        else {
            $slb003Status = 'PASS'
            $slb003Detail = "$($autoLabelPolicies.Count) auto-labeling policy/policies configured."
        }
    }
    catch {
        $slb003Status = 'LOW'
        $slb003Detail = "Auto-labeling policies could not be retrieved (may require E5 license or additional permissions). Manual-only labeling is assumed. Error: $_"
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
    # -------------------------------------------------------------------------
    $mandatoryLabelingEnabled = $false
    if ($labelPolicies -and $labelPolicies.Count -gt 0) {
        foreach ($policy in $labelPolicies) {
            if ($policy.settings -and (
                $policy.settings | Where-Object { $_.key -eq 'requiredowngradejustification' -or $_.key -eq 'mandatory' -and $_.value -eq 'true' }
            )) {
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
    # -------------------------------------------------------------------------
    $confidentialLabels = @($labels | Where-Object {
        $_.name -match 'Confidential|Highly Confidential|Restricted|Secret' -or
        $_.displayName -match 'Confidential|Highly Confidential|Restricted|Secret'
    })

    if ($confidentialLabels.Count -eq 0) {
        $slb005Status = 'MEDIUM'
        $slb005Detail = 'No labels with "Confidential" or "Highly Confidential" naming found. Cannot verify encryption requirement for sensitive labels.'
    }
    else {
        $labelsWithEncryption = @($confidentialLabels | Where-Object {
            $_.contentFormats -contains 'email' -or
            $null -ne $_.encryptionDelegatedUserEmailAddress -or
            ($_.labelActions | Where-Object { $_.value -match 'encrypt' })
        })

        # Also check via label details
        $labelsWithoutEncryption = [System.Collections.Generic.List[string]]::new()
        foreach ($label in $confidentialLabels) {
            try {
                $labelDetail = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/security/informationProtection/sensitivityLabels/$($label.id)" `
                    -ErrorAction Stop
                if ($null -eq $labelDetail.encryptionDelegatedUserEmailAddress -and
                    -not ($labelDetail.labelActions | Where-Object { $_.value -match 'encrypt' })) {
                    $labelsWithoutEncryption.Add($label.name)
                }
            }
            catch {
                Write-Verbose "Could not get label detail for $($label.name): $_"
            }
        }

        if ($labelsWithoutEncryption.Count -gt 0) {
            $slb005Status = 'HIGH'
            $slb005Detail = "Confidential labels without confirmed encryption: $($labelsWithoutEncryption -join ', '). Sensitive content may not be protected even when labeled."
        }
        else {
            $slb005Status = 'PASS'
            $slb005Detail = "$($confidentialLabels.Count) confidential label(s) found. Encryption configuration could not be definitively confirmed via API — verify in Purview portal."
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
