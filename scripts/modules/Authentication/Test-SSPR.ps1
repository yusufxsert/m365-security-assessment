#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Checks Self-Service Password Reset (SSPR) configuration.
.DESCRIPTION
    Evaluates SSPR enablement scope, required auth gate count, writeback
    configuration for hybrid tenants, and registration campaign status.
    Checks: SSP-001 through SSP-004.
.NOTES
    Required Permissions:
        Policy.Read.All
        Directory.Read.All
        Organization.Read.All
    License: E3 minimum for basic SSPR; writeback requires hybrid + E3
    Note: SSPR policy is only fully available via the beta endpoint.
          The v1.0 endpoint does not expose selfServicePasswordResetPolicy.
#>

function Test-SSPR {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Detect hybrid status once — used for SSP-003
    $isHybrid = $false
    try {
        $org = Get-MgOrganization -Property 'onPremisesSyncEnabled' -ErrorAction Stop
        $isHybrid = $org.OnPremisesSyncEnabled -eq $true
    }
    catch {
        Write-Verbose "Could not determine hybrid status: $_"
    }

    # SSP-001: SSPR enablement scope
    try {
        # SSPR policy is exposed via beta endpoint
        $sspr = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/policies/selfServicePasswordResetPolicy' `
            -ErrorAction Stop

        $isEnabled = $sspr.isEnabled
        $scope = $sspr.allowedToResetPassword  # can be 'all', 'none', or group-based

        # Determine scope description
        $scopeDesc = if (-not $isEnabled) {
            'SSPR is DISABLED for all users'
        } elseif ($scope -eq 'all') {
            'SSPR is enabled for ALL users'
        } elseif ($scope -eq 'none') {
            'SSPR is enabled in policy but allowedToResetPassword is none — effectively disabled'
        } else {
            "SSPR is enabled for selected groups (scope: $scope)"
        }

        $status = if (-not $isEnabled -or $scope -eq 'none') { 'Fail' }
                  elseif ($scope -ne 'all') { 'Warning' }
                  else { 'Pass' }

        $results.Add((New-AssessmentResult `
            -CheckName 'SSP-001: SSPR Enablement Scope' `
            -Status    $status `
            -Detail    $scopeDesc `
            -Recommendation 'Enable SSPR for all users. SSPR reduces helpdesk burden and allows users to recover accounts without admin intervention. Without SSPR, password resets require helpdesk tickets.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks' `
            -Category  'Authentication' `
            -Severity  (if ($status -eq 'Fail') { 'High' } else { 'Medium' }) `
            -CisControl 'CIS M365 1.1.3'))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'SSP-001: SSPR Enablement' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or beta endpoint unavailable. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal. The SSPR policy is only available via the /beta endpoint.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-howitworks' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # SSP-002: Number of required authentication gates
    try {
        $sspr = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/policies/selfServicePasswordResetPolicy' `
            -ErrorAction Stop

        $numberOfGates = $sspr.numberOfMethodsForReset
        $registeredMethods = $sspr.registrationRequiredByPolicy

        $status = if ($null -eq $numberOfGates) { 'Info' }
                  elseif ($numberOfGates -lt 2) { 'Warning' }
                  else { 'Pass' }

        $results.Add((New-AssessmentResult `
            -CheckName 'SSP-002: SSPR Authentication Gates Required' `
            -Status    $status `
            -Detail    "Number of methods required for SSPR: $numberOfGates. With only 1 gate, social engineering attacks on the reset flow become easier." `
            -Recommendation 'Set numberOfMethodsForReset to 2. This requires users to verify via two independent methods before resetting their password.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy' `
            -Category  'Authentication' `
            -Severity  (if ($status -eq 'Warning') { 'Medium' } else { 'Info' }) `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'SSP-002: SSPR Gate Count' `
            -Status    'Info' `
            -Detail    "Check skipped: beta endpoint unavailable. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    # SSP-003: SSPR writeback to on-premises (hybrid only)
    if (-not $isHybrid) {
        $results.Add((New-AssessmentResult `
            -CheckName 'SSP-003: SSPR Writeback (Hybrid)' `
            -Status    'Info' `
            -Detail    "Tenant is cloud-only (onPremisesSyncEnabled: false). SSPR writeback check is not applicable." `
            -Recommendation 'No action required for cloud-only tenants.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/concept-sspr-writeback' `
            -Category  'Authentication' `
            -Severity  'Info' `
            -CisControl ''))
    }
    else {
        try {
            # SSPR writeback configuration is in beta policy endpoint
            $sspr = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/beta/policies/selfServicePasswordResetPolicy' `
                -ErrorAction Stop

            # writebackEnabled is the relevant field
            $writebackEnabled = $sspr.writebackEnabled

            $results.Add((New-AssessmentResult `
                -CheckName 'SSP-003: SSPR Writeback to On-Premises' `
                -Status    (if ($writebackEnabled -eq $true) { 'Pass' } else { 'Fail' }) `
                -Detail    "SSPR writeback enabled: $writebackEnabled. Hybrid tenant detected (onPremisesSyncEnabled: true). Without writeback, cloud-reset passwords are not synced back to on-premises AD." `
                -Recommendation 'Enable SSPR writeback in Entra Connect configuration. Ensure the AD account used by Entra Connect has reset password permissions in AD.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-sspr-writeback' `
                -Category  'Authentication' `
                -Severity  (if ($writebackEnabled -ne $true) { 'High' } else { 'Info' }) `
                -CisControl ''))
        }
        catch {
            $results.Add((New-AssessmentResult `
                -CheckName 'SSP-003: SSPR Writeback' `
                -Status    'Info' `
                -Detail    "Check skipped: beta endpoint unavailable. Required: Policy.Read.All. Error: $_" `
                -Recommendation 'Grant Policy.Read.All to the service principal.' `
                -Reference 'https://learn.microsoft.com/entra/identity/authentication/howto-sspr-writeback' `
                -Category  'Authentication' `
                -Severity  'Info'))
        }
    }

    # SSP-004: SSPR registration campaign
    try {
        $authMethodsPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
            -ErrorAction Stop

        $campaign = $authMethodsPolicy.registrationEnforcement.authenticationMethodsRegistrationCampaign
        $campaignState = $campaign.state
        $snoozeCount = $campaign.snoozeDurationInDays
        $enforceRegistration = $campaign.enforceRegistration

        $results.Add((New-AssessmentResult `
            -CheckName 'SSP-004: SSPR Registration Campaign' `
            -Status    (if ($campaignState -eq 'enabled') { 'Pass' } else { 'Warning' }) `
            -Detail    "Registration campaign state: $campaignState. Enforce registration: $enforceRegistration. Snooze duration: $snoozeCount days." `
            -Recommendation 'Enable the registration campaign (state: enabled, enforceRegistration: true, snoozeDurationInDays: 0 for mandatory). This prompts users to register/update auth methods at sign-in.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-registration-campaign' `
            -Category  'Authentication' `
            -Severity  (if ($campaignState -ne 'enabled') { 'Low' } else { 'Info' }) `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'SSP-004: Registration Campaign' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-registration-campaign' `
            -Category  'Authentication' `
            -Severity  'Info'))
    }

    return $results
}
