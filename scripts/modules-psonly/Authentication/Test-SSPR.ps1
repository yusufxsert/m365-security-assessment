#Requires -Version 7.0

<#
.SYNOPSIS
    Checks Self-Service Password Reset (SSPR) configuration. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — converts New-CheckResult → New-CheckResult, and uses
    Get-MgPolicyAuthenticationMethodPolicy (PS-only) for SSP-004 instead of
    raw Invoke-MgGraphRequest.

    WHY PS-ONLY:
    The original uses New-CheckResult (different helper with different parameters).
    This variant uses New-CheckResult with the standard CheckId-based parameter set.

    NOTE on SSP-001 and SSP-002 (SSPR policy):
    /beta/policies/selfServicePasswordResetPolicy has NO Get-Mg* equivalent in the
    current Microsoft.Graph.Identity.SignIns module. These checks use Invoke-MgGraphRequest
    targeting the beta endpoint — this is the only way to access SSPR policy settings.
    This is intentional and documented; the beta endpoint is stable and widely used.

    SSP-004 (Registration Campaign):
    Get-MgPolicyAuthenticationMethodPolicy is the PS-only equivalent of
    /v1.0/policies/authenticationMethodsPolicy. The registrationEnforcement
    campaign property is accessible via .RegistrationEnforcement.

    SEE ALSO (Graph variant):
        scripts/modules/Authentication/Test-SSPR.ps1

    Required connection:
        Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All","Organization.Read.All"

    Required scopes:
        Policy.Read.All
        Directory.Read.All
        Organization.Read.All

    Required modules:
        Microsoft.Graph.Identity.DirectoryManagement  (Get-MgOrganization)
        Microsoft.Graph.Authentication                (Invoke-MgGraphRequest for beta SSPR)
        Microsoft.Graph.Identity.SignIns              (Get-MgPolicyAuthenticationMethodPolicy)

    License: E3 minimum for basic SSPR; writeback requires hybrid + E3
    SC-300 Domain: Authentication & Access Management

    Note: SSPR policy is only fully available via the beta endpoint.
          The v1.0 endpoint does not expose selfServicePasswordResetPolicy.

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.

    Status mapping from original (New-CheckResult) to New-CheckResult:
        Pass    → PASS
        Warning → MEDIUM
        Fail    → HIGH
        Info    → INFO
#>

function Test-SSPR {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Detect hybrid status once — used for SSP-003
    # Get-MgOrganization is the PS-only equivalent of GET /organization
    # -------------------------------------------------------------------------
    $isHybrid = $false
    try {
        $org      = Get-MgOrganization -Property 'onPremisesSyncEnabled' -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled -eq $true
    }
    catch {
        Write-Verbose "Could not determine hybrid status: $_"
    }

    # -------------------------------------------------------------------------
    # SSP-001: SSPR enablement scope
    # No Get-Mg* for beta/policies/selfServicePasswordResetPolicy
    # Invoke-MgGraphRequest is the confirmed path (beta endpoint)
    # -------------------------------------------------------------------------
    $ssprPolicy = $null
    try {
        $ssprPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/policies/selfServicePasswordResetPolicy' `
            -ErrorAction Stop

        $isEnabled = $ssprPolicy.isEnabled
        $scope     = $ssprPolicy.allowedToResetPassword  # 'all', 'none', or group-based

        $scopeDesc = if (-not $isEnabled) {
            'SSPR is DISABLED for all users'
        }
        elseif ($scope -eq 'all') {
            'SSPR is enabled for ALL users'
        }
        elseif ($scope -eq 'none') {
            'SSPR is enabled in policy but allowedToResetPassword is none — effectively disabled'
        }
        else {
            "SSPR is enabled for selected groups (scope: $scope)"
        }

        $ssp001Status = if (-not $isEnabled -or $scope -eq 'none') { 'HIGH' }
                        elseif ($scope -ne 'all') { 'MEDIUM' }
                        else { 'PASS' }

        $results.Add((New-CheckResult `
            -CheckId        'SSP-001' `
            -Category       'Authentication' `
            -Name           'SSPR Enablement Scope' `
            -Status         $ssp001Status `
            -Detail         $scopeDesc `
            -Recommendation 'Enable SSPR for all users. SSPR reduces helpdesk burden and allows users to recover accounts without admin intervention. Without SSPR, password resets require helpdesk tickets.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks' `
            -CISControl     'CIS M365 1.1.3' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'SSP-001' `
            -Category       'Authentication' `
            -Name           'SSPR Enablement Scope' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or beta endpoint unavailable. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All". The SSPR policy is only available via the /beta endpoint.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks' `
            -CISControl     'CIS M365 1.1.3' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SSP-002: Number of required authentication gates
    # Re-uses $ssprPolicy from SSP-001 or re-fetches if needed
    # -------------------------------------------------------------------------
    try {
        if ($null -eq $ssprPolicy) {
            $ssprPolicy = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/policies/selfServicePasswordResetPolicy' `
                -ErrorAction Stop
        }

        $numberOfGates = $ssprPolicy.numberOfMethodsForReset

        $ssp002Status = if ($null -eq $numberOfGates) { 'INFO' }
                        elseif ($numberOfGates -lt 2) { 'MEDIUM' }
                        else { 'PASS' }

        $results.Add((New-CheckResult `
            -CheckId        'SSP-002' `
            -Category       'Authentication' `
            -Name           'SSPR Authentication Gates Required' `
            -Status         $ssp002Status `
            -Detail         "Number of methods required for SSPR: $numberOfGates. With only 1 gate, social engineering attacks on the reset flow become easier." `
            -Recommendation 'Set numberOfMethodsForReset to 2. This requires users to verify via two independent methods before resetting their password.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'SSP-002' `
            -Category       'Authentication' `
            -Name           'SSPR Authentication Gates Required' `
            -Status         'INFO' `
            -Detail         "Check skipped: beta endpoint unavailable. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # SSP-003: SSPR writeback to on-premises (hybrid only)
    # -------------------------------------------------------------------------
    if (-not $isHybrid) {
        $results.Add((New-CheckResult `
            -CheckId        'SSP-003' `
            -Category       'Authentication' `
            -Name           'SSPR Writeback (Hybrid)' `
            -Status         'INFO' `
            -Detail         'Tenant is cloud-only (onPremisesSyncEnabled: false). SSPR writeback check is not applicable.' `
            -Recommendation 'No action required for cloud-only tenants.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-writeback' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    else {
        try {
            if ($null -eq $ssprPolicy) {
                $ssprPolicy = Invoke-MgGraphRequest -Method GET `
                    -Uri 'https://graph.microsoft.com/beta/policies/selfServicePasswordResetPolicy' `
                    -ErrorAction Stop
            }

            $writebackEnabled = $ssprPolicy.writebackEnabled

            $results.Add((New-CheckResult `
                -CheckId        'SSP-003' `
                -Category       'Authentication' `
                -Name           'SSPR Writeback to On-Premises' `
                -Status         (if ($writebackEnabled -eq $true) { 'PASS' } else { 'HIGH' }) `
                -Detail         "SSPR writeback enabled: $writebackEnabled. Hybrid tenant detected (onPremisesSyncEnabled: true). Without writeback, cloud-reset passwords are not synced back to on-premises AD." `
                -Recommendation 'Enable SSPR writeback in Entra Connect configuration. Ensure the AD account used by Entra Connect has reset password permissions in AD.' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-sspr-writeback' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId        'SSP-003' `
                -Category       'Authentication' `
                -Name           'SSPR Writeback (Hybrid)' `
                -Status         'INFO' `
                -Detail         "Check skipped: beta endpoint unavailable. Required: Policy.Read.All. Error: $_" `
                -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
                -Reference      'https://learn.microsoft.com/entra/identity/authentication/howto-sspr-writeback' `
                -CISControl     '' `
                -SC300Domain    'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }

    # -------------------------------------------------------------------------
    # SSP-004: SSPR registration campaign
    # PS-ONLY: Get-MgPolicyAuthenticationMethodPolicy
    # This is the v1.0 equivalent of /policies/authenticationMethodsPolicy
    # -------------------------------------------------------------------------
    try {
        $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop

        # registrationEnforcement.authenticationMethodsRegistrationCampaign
        $campaign     = $authMethodsPolicy.RegistrationEnforcement.AuthenticationMethodsRegistrationCampaign
        $campaignState = $campaign.State
        $snoozeCount   = $campaign.SnoozeDurationInDays
        $enforceReg    = $campaign.EnforceRegistration

        $ssp004Status = if ($campaignState -eq 'enabled') { 'PASS' } else { 'MEDIUM' }

        $results.Add((New-CheckResult `
            -CheckId        'SSP-004' `
            -Category       'Authentication' `
            -Name           'SSPR Registration Campaign' `
            -Status         $ssp004Status `
            -Detail         "Registration campaign state: $campaignState. Enforce registration: $enforceReg. Snooze duration: $snoozeCount days." `
            -Recommendation 'Enable the registration campaign (state: enabled, enforceRegistration: true, snoozeDurationInDays: 0 for mandatory). This prompts users to register/update auth methods at sign-in.' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/how-to-registration-campaign' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId        'SSP-004' `
            -Category       'Authentication' `
            -Name           'SSPR Registration Campaign' `
            -Status         'INFO' `
            -Detail         "Check skipped: insufficient permissions or Get-MgPolicyAuthenticationMethodPolicy failed. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "Policy.Read.All".' `
            -Reference      'https://learn.microsoft.com/entra/identity/authentication/how-to-registration-campaign' `
            -CISControl     '' `
            -SC300Domain    'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
