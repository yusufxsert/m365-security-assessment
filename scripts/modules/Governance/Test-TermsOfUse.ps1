#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests Terms of Use configuration and enforcement via Conditional Access.

.DESCRIPTION
    Checks whether Terms of Use (ToU) agreements are configured, enforced via
    Conditional Access policies, require periodic re-acceptance, and tracks
    overall user acceptance coverage.

.NOTES
    Required Permissions:
        - Agreement.Read.All
        - Policy.Read.All          (for CA policy enforcement check)

    License: Entra ID P1 / Microsoft 365 E3 (Terms of Use requires at least P1)
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/Governance/Test-TermsOfUse.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
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
        $agreementsUri = 'https://graph.microsoft.com/v1.0/agreements?$top=999'
        $agreementsResponse = Invoke-MgGraphRequest -Method GET -Uri $agreementsUri -ErrorAction Stop
        $agreements = $agreementsResponse.value
        $count = ($agreements | Measure-Object).Count

        if ($count -eq 0) {
            $status = 'LOW'
            $detail = 'No Terms of Use agreements configured. ToU is a compliance and awareness control that documents user accountability for acceptable use.'
        }
        else {
            $touList = $agreements | ForEach-Object {
                "'$($_.displayName)' (isViewingBeforeAcceptanceRequired: $($_.isViewingBeforeAcceptanceRequired), reacceptRequired: $($_.termsExpiration.frequency ?? 'never'))"
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
            -Recommendation 'Configure a Terms of Use agreement covering acceptable use, data handling, and security responsibilities. Enforce it via Conditional Access. ToU acceptance is logged in Entra audit logs and can be used as a compliance artifact.' `
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
            -Recommendation 'Grant Agreement.Read.All permission.' `
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
        $caUri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=999'
        $caResponse = Invoke-MgGraphRequest -Method GET -Uri $caUri -ErrorAction Stop
        $caPolicies = $caResponse.value

        # Find CA policies that reference a ToU in grant controls
        $touEnforcingPolicies = $caPolicies | Where-Object {
            $_.state -eq 'enabled' -and
            $null -ne $_.grantControls -and
            ($_.grantControls.termsOfUse | Measure-Object).Count -gt 0
        }

        $touCount    = ($agreements | Measure-Object).Count
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
            $enforcedPolicies = ($touEnforcingPolicies.displayName) -join ', '
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
            -Recommendation 'Grant Policy.Read.All permission.' `
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
            $expiration = $agreement.termsExpiration
            $reacceptRequired = $agreement.isPerDeviceAcceptanceRequired

            # If termsExpiration is null or frequency is not set, ToU never expires
            $hasReaccept = (
                $null -ne $expiration -and
                $null -ne $expiration.frequency -and
                $expiration.frequency -ne 'PT0S' -and
                $expiration.startDateTime -ne $null
            )

            if (-not $hasReaccept) {
                $noReacceptAgreements.Add("'$($agreement.displayName)' — never requires re-acceptance")
            }
        }

        if ($noReacceptAgreements.Count -gt 0) {
            $status = 'LOW'
            $detail = "$($noReacceptAgreements.Count) agreement(s) never require re-acceptance: $($noReacceptAgreements -join '; '). Once-only acceptance means users can forget terms and the agreement becomes stale."
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
            -Recommendation 'Configure Terms of Use with annual or semi-annual re-acceptance requirement (set termsExpiration.frequency). This ensures ongoing user awareness and provides a more current audit trail of acceptance.' `
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
    # -------------------------------------------------------------------------
    try {
        foreach ($agreement in $agreements) {
            $agreementId = $agreement.id
            $acceptancesUri = "https://graph.microsoft.com/v1.0/agreements/$agreementId/acceptances?`$top=999"
            try {
                $acceptancesResponse = Invoke-MgGraphRequest -Method GET -Uri $acceptancesUri -ErrorAction Stop
                $acceptances = $acceptancesResponse.value

                $acceptedCount  = ($acceptances | Where-Object { $_.state -eq 'accepted'  } | Measure-Object).Count
                $declinedCount  = ($acceptances | Where-Object { $_.state -eq 'declined'  } | Measure-Object).Count
                $pendingCount   = ($acceptances | Where-Object { $_.state -eq 'notYetAccepted' } | Measure-Object).Count
                $totalCount     = ($acceptances | Measure-Object).Count

                $acceptancePct = if ($totalCount -gt 0) {
                    [math]::Round(($acceptedCount / $totalCount) * 100, 1)
                } else { 0 }

                $results.Add((New-CheckResult `
                    -CheckId 'TOU-004' `
                    -Category 'Governance' `
                    -Name "Terms of Use acceptance coverage – '$($agreement.displayName)'" `
                    -Status 'INFO' `
                    -Detail "Agreement: '$($agreement.displayName)' | Accepted: $acceptedCount | Declined: $declinedCount | Pending: $pendingCount | Total: $totalCount | Acceptance rate: $acceptancePct%." `
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
                    -Name "Terms of Use acceptance coverage – '$($agreement.displayName)'" `
                    -Status 'INFO' `
                    -Detail "Could not retrieve acceptance records for agreement '$($agreement.displayName)': $_" `
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
