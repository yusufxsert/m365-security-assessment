#Requires -Version 7.0

<#
.SYNOPSIS
    Tests Terms of Use configuration and enforcement via Conditional Access. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgAgreement (Identity.Governance) and
    Get-MgIdentityConditionalAccessPolicy (Identity.SignIns) instead of raw
    Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    Get-MgAgreement provides the same data as /agreements with strongly-typed
    output objects. Get-MgAgreementAcceptance provides acceptance records per
    agreement. Both cmdlets handle pagination automatically.

    SEE ALSO (Graph variant):
        scripts/modules/Governance/Test-TermsOfUse.ps1

    Required connection:
        Connect-MgGraph -Scopes "Agreement.Read.All","Policy.Read.All"

    Required scopes:
        Agreement.Read.All
        Policy.Read.All  (for CA policy enforcement check)

    Required modules:
        Microsoft.Graph.Identity.Governance
        Microsoft.Graph.Identity.SignIns

    License: Entra ID P1 / Microsoft 365 E3
    SC-300 Domain: Identity Governance

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-TermsOfUse {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # TOU-001: Terms of Use configured
    # -------------------------------------------------------------------------
    $agreements = $null

    try {
        $agreements = Get-MgAgreement -All -ErrorAction Stop
        $count      = ($agreements | Measure-Object).Count

        if ($count -eq 0) {
            $status = 'LOW'
            $detail = 'No Terms of Use agreements configured. ToU is a compliance and awareness control that documents user accountability for acceptable use.'
        }
        else {
            $touList = $agreements | ForEach-Object {
                $freq = $_.TermsExpiration.Frequency ?? 'never'
                "'$($_.DisplayName)' (isViewingBeforeAcceptanceRequired: $($_.IsViewingBeforeAcceptanceRequired), reacceptRequired: $freq)"
            }
            $status = 'PASS'
            $detail = "$count Terms of Use agreement(s) found: $($touList -join ' | ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'TOU-001' `
            -Category 'Governance' `
            -Name 'Terms of Use configured' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Configure a Terms of Use agreement covering acceptable use, data handling, and security responsibilities. Enforce it via Conditional Access. ToU acceptance is logged in Entra audit logs.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'TOU-001' `
            -Category 'Governance' `
            -Name 'Terms of Use configured' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Agreement.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Agreement.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # TOU-002: ToU assigned to CA policy
    # -------------------------------------------------------------------------
    try {
        $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop

        $touEnforcingPolicies = $caPolicies | Where-Object {
            $_.State -eq 'enabled' -and
            $null -ne $_.GrantControls -and
            ($_.GrantControls.TermsOfUse | Measure-Object).Count -gt 0
        }

        $touCount      = ($agreements | Measure-Object).Count
        $enforcedCount = ($touEnforcingPolicies | Measure-Object).Count

        if ($touCount -gt 0 -and $enforcedCount -eq 0) {
            $status = 'LOW'
            $detail = "Terms of Use exist ($touCount agreement(s)) but none are enforced via an enabled Conditional Access policy. Users may not encounter the ToU during sign-in."
        }
        elseif ($touCount -eq 0) {
            $status = 'INFO'
            $detail = 'No Terms of Use configured — CA enforcement check not applicable.'
        }
        else {
            $enforcedPolicies = ($touEnforcingPolicies | ForEach-Object { $_.DisplayName }) -join ', '
            $status = 'PASS'
            $detail = "Terms of Use enforced via CA policy: $enforcedPolicies."
        }

        $results.Add((New-CheckResult `
            -CheckId 'TOU-002' `
            -Category 'Governance' `
            -Name 'Terms of Use enforced via Conditional Access' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Add Terms of Use as a grant control in at least one Conditional Access policy targeting all users. Consider applying ToU at first sign-in and on a recurring schedule.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use#create-a-conditional-access-policy' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'TOU-002' `
            -Category 'Governance' `
            -Name 'Terms of Use enforced via Conditional Access' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use#create-a-conditional-access-policy' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # TOU-003: ToU re-acceptance frequency
    # -------------------------------------------------------------------------
    try {
        $noReacceptAgreements = [System.Collections.Generic.List[string]]::new()

        foreach ($agreement in $agreements) {
            $expiration = $agreement.TermsExpiration
            $hasReaccept = (
                $null -ne $expiration -and
                $null -ne $expiration.Frequency -and
                $expiration.Frequency -ne 'PT0S' -and
                $null -ne $expiration.StartDateTime
            )

            if (-not $hasReaccept) {
                $noReacceptAgreements.Add("'$($agreement.DisplayName)' — never requires re-acceptance")
            }
        }

        if ($noReacceptAgreements.Count -gt 0) {
            $status = 'LOW'
            $detail = "$($noReacceptAgreements.Count) agreement(s) never require re-acceptance: $($noReacceptAgreements -join '; ')."
        }
        elseif (($agreements | Measure-Object).Count -eq 0) {
            $status = 'INFO'
            $detail = 'No Terms of Use configured.'
        }
        else {
            $status = 'PASS'
            $detail = 'All Terms of Use agreements are configured to require periodic re-acceptance.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'TOU-003' `
            -Category 'Governance' `
            -Name 'Terms of Use re-acceptance frequency' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Configure Terms of Use with annual or semi-annual re-acceptance requirement. This ensures ongoing user awareness and provides a more current audit trail.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use#require-reacceptance' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects $noReacceptAgreements.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'TOU-003' `
            -Category 'Governance' `
            -Name 'Terms of Use re-acceptance frequency' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use#require-reacceptance' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # TOU-004: ToU acceptance coverage – INFO
    # Get-MgAgreementAcceptance -AgreementId {id} -All
    # -------------------------------------------------------------------------
    try {
        foreach ($agreement in $agreements) {
            try {
                $acceptances = Get-MgAgreementAcceptance -AgreementId $agreement.Id -All -ErrorAction Stop

                $acceptedCount = ($acceptances | Where-Object { $_.State -eq 'accepted' } | Measure-Object).Count
                $declinedCount = ($acceptances | Where-Object { $_.State -eq 'declined' } | Measure-Object).Count
                $pendingCount  = ($acceptances | Where-Object { $_.State -eq 'notYetAccepted' } | Measure-Object).Count
                $totalCount    = ($acceptances | Measure-Object).Count

                $acceptancePct = if ($totalCount -gt 0) {
                    [math]::Round(($acceptedCount / $totalCount) * 100, 1)
                } else { 0 }

                $results.Add((New-CheckResult `
                    -CheckId 'TOU-004' `
                    -Category 'Governance' `
                    -Name "Terms of Use acceptance coverage – '$($agreement.DisplayName)'" `
                    -Status 'INFO' `
                    -Detail "Agreement: '$($agreement.DisplayName)' | Accepted: $acceptedCount | Declined: $declinedCount | Pending: $pendingCount | Total: $totalCount | Acceptance rate: $acceptancePct%." `
                    -Recommendation 'Follow up with users who have not accepted the Terms of Use. Users who decline should be escalated to their manager. Consider blocking access via CA policy until ToU is accepted.' `
                    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use#view-report-of-who-has-accepted-and-declined' `
                    -CISControl '' `
                    -SC300Domain 'Identity Governance' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @("Accepted: $acceptedCount", "Declined: $declinedCount", "Pending: $pendingCount")))
            }
            catch {
                $results.Add((New-CheckResult `
                    -CheckId 'TOU-004' `
                    -Category 'Governance' `
                    -Name "Terms of Use acceptance coverage – '$($agreement.DisplayName)'" `
                    -Status 'INFO' `
                    -Detail "Could not retrieve acceptance records for agreement '$($agreement.DisplayName)': $_" `
                    -Recommendation 'Ensure Agreement.Read.All permission includes acceptance records access.' `
                    -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use#view-report-of-who-has-accepted-and-declined' `
                    -CISControl '' `
                    -SC300Domain 'Identity Governance' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }

        if (($agreements | Measure-Object).Count -eq 0) {
            $results.Add((New-CheckResult `
                -CheckId 'TOU-004' `
                -Category 'Governance' `
                -Name 'Terms of Use acceptance coverage' `
                -Status 'INFO' `
                -Detail 'No Terms of Use agreements configured.' `
                -Recommendation 'Configure Terms of Use agreements before checking acceptance coverage.' `
                -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use' `
                -CISControl '' `
                -SC300Domain 'Identity Governance' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'TOU-004' `
            -Category 'Governance' `
            -Name 'Terms of Use acceptance coverage' `
            -Status 'INFO' `
            -Detail "Check failed unexpectedly. Error: $_" `
            -Recommendation 'Investigate error and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
