#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Checks Entra ID tenant-level security configuration.
.DESCRIPTION
    Evaluates Security Defaults, tenant display name hygiene, SSPR registration campaign,
    password hash sync (hybrid), and B2B collaboration domain restrictions.
    Checks: IAM-001 through IAM-005.
.NOTES
    Required Permissions:
        Policy.Read.All
        Directory.Read.All
        Organization.Read.All
    License: E3 minimum; E5 for full CA conflict detection
#>

function Test-EntraTenantConfig {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # IAM-001: Security Defaults status
    try {
        $org = Get-MgOrganization -ErrorAction Stop
        $secDefaults = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
            -ErrorAction Stop

        $secDefaultsEnabled = $secDefaults.isEnabled

        # Check for E5 licenses (securityDefaults conflicts with CA on E5)
        $hasE5 = $org | ForEach-Object { $_.AssignedPlans } |
            Where-Object { $_.ServicePlanId -in @(
                'efb87545-963c-4e0d-99df-69c6916d9eb0', # AAD_PREMIUM_P2
                'b05e124f-c7cc-45a0-a6aa-8cf78c946968'  # ENTERPRISEPREMIUM (E5)
            ) -and $_.CapabilityStatus -eq 'Enabled' } |
            Select-Object -First 1

        if ($secDefaultsEnabled) {
            # Check for any enabled CA policies (conflict)
            $caPolicies = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$filter=state eq ''enabled''' `
                -ErrorAction SilentlyContinue
            $enabledCaCount = if ($caPolicies.value) { $caPolicies.value.Count } else { 0 }

            if ($enabledCaCount -gt 0) {
                $results.Add((New-AssessmentResult `
                    -CheckName 'IAM-001: Security Defaults vs Conditional Access Conflict' `
                    -Status    'Fail' `
                    -Detail    "Security Defaults is ENABLED but $enabledCaCount enabled CA policies also exist. This is a configuration conflict — Security Defaults and CA policies cannot coexist safely." `
                    -Recommendation 'Disable Security Defaults before deploying Conditional Access policies. Migrate all Security Defaults protections to equivalent CA policies first.' `
                    -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults' `
                    -Category  'Identity' `
                    -Severity  'Critical' `
                    -CisControl 'CIS M365 1.1.1'))
            }
            elseif ($hasE5) {
                $results.Add((New-AssessmentResult `
                    -CheckName 'IAM-001: Security Defaults on E5 Tenant' `
                    -Status    'Fail' `
                    -Detail    "Security Defaults is ENABLED on an E5-licensed tenant. E5 includes Conditional Access; Security Defaults should be replaced with CA policies for granular control." `
                    -Recommendation 'Disable Security Defaults and implement Conditional Access policies aligned with Microsoft Secure Score recommendations (MFA for all users, block legacy auth, etc.).' `
                    -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults' `
                    -Category  'Identity' `
                    -Severity  'High' `
                    -CisControl 'CIS M365 1.1.1'))
            }
            else {
                $results.Add((New-AssessmentResult `
                    -CheckName 'IAM-001: Security Defaults Enabled' `
                    -Status    'Info' `
                    -Detail    "Security Defaults is ENABLED. For an E3 tenant without Conditional Access, this is an acceptable baseline providing MFA prompts, legacy auth blocking, and admin MFA enforcement." `
                    -Recommendation 'Acceptable for E3 tenants. When upgrading to E5/P2, disable Security Defaults and implement Conditional Access policies for finer control.' `
                    -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults' `
                    -Category  'Identity' `
                    -Severity  'Info' `
                    -CisControl 'CIS M365 1.1.1'))
            }
        }
        else {
            $results.Add((New-AssessmentResult `
                -CheckName 'IAM-001: Security Defaults Disabled' `
                -Status    'Pass' `
                -Detail    "Security Defaults is DISABLED. Ensure Conditional Access policies cover the equivalent protections (MFA for all users, block legacy auth, admin MFA)." `
                -Recommendation 'Verify CA policies exist to block legacy auth and enforce MFA. Run Test-ConditionalAccessPolicies for coverage details.' `
                -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl 'CIS M365 1.1.1'))
        }
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-001: Security Defaults' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/fundamentals/security-defaults' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # IAM-002: Tenant display name configured
    try {
        $org = Get-MgOrganization -ErrorAction Stop
        $tenantName = $org.DisplayName
        $hasName = -not [string]::IsNullOrWhiteSpace($tenantName)

        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-002: Tenant Display Name Configured' `
            -Status    (if ($hasName) { 'Pass' } else { 'Fail' }) `
            -Detail    (if ($hasName) { "Tenant display name is set." } else { "Tenant display name is empty or null. Basic hygiene issue." }) `
            -Recommendation 'Set a descriptive tenant display name in Entra ID admin center under Overview.' `
            -Reference 'https://learn.microsoft.com/entra/fundamentals/how-to-manage-tenant' `
            -Category  'Identity' `
            -Severity  'Low' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-002: Tenant Display Name' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: Organization.Read.All. Error: $_" `
            -Recommendation 'Grant Organization.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/fundamentals/how-to-manage-tenant' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # IAM-003: SSPR registration campaign
    try {
        $authMethodsPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' `
            -ErrorAction Stop

        $campaignState = $authMethodsPolicy.registrationEnforcement.authenticationMethodsRegistrationCampaign.state
        $campaignEnabled = $campaignState -eq 'enabled'

        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-003: SSPR Registration Campaign' `
            -Status    (if ($campaignEnabled) { 'Pass' } else { 'Warning' }) `
            -Detail    "Registration campaign state: $campaignState. A registration campaign prompts users to register authentication methods at next sign-in." `
            -Recommendation 'Enable the authentication methods registration campaign to drive adoption of modern auth methods (Authenticator app, FIDO2).' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-registration-campaign' `
            -Category  'Identity' `
            -Severity  'Low' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-003: SSPR Registration Campaign' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/authentication/how-to-registration-campaign' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # IAM-004: Password hash sync (hybrid)
    try {
        $org = Get-MgOrganization -Property 'onPremisesSyncEnabled,displayName' -ErrorAction Stop
        $syncEnabled = $org.OnPremisesSyncEnabled

        if ($syncEnabled -eq $true) {
            $results.Add((New-AssessmentResult `
                -CheckName 'IAM-004: Password Hash Sync (Hybrid)' `
                -Status    'Pass' `
                -Detail    "OnPremisesSyncEnabled: true. Directory sync is active. Password Hash Sync should be verified separately via Entra Connect Health." `
                -Recommendation 'Confirm Password Hash Sync is enabled in Entra Connect (vs Pass-through Auth or Federation). PHS provides leaked credential detection and resilience.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-phs' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl ''))
        }
        elseif ($syncEnabled -eq $false -or $null -eq $syncEnabled) {
            $results.Add((New-AssessmentResult `
                -CheckName 'IAM-004: Password Hash Sync (Hybrid)' `
                -Status    'Info' `
                -Detail    "OnPremisesSyncEnabled: false/null. This appears to be a cloud-only tenant. Password Hash Sync check is not applicable." `
                -Recommendation 'No action required for cloud-only tenants.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-phs' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl ''))
        }
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-004: Password Hash Sync' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: Organization.Read.All. Error: $_" `
            -Recommendation 'Grant Organization.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-phs' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # IAM-005: B2B collaboration / allowed external domains
    try {
        $crossTenantPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy' `
            -ErrorAction Stop

        $defaultPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' `
            -ErrorAction Stop

        $partners = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners' `
            -ErrorAction Stop

        $partnerCount = if ($partners.value) { $partners.value.Count } else { 0 }

        # Check if inbound B2B is unrestricted (allowAllUsers true or no specific users block)
        $inboundB2B = $defaultPolicy.b2bCollaborationInbound
        $inboundAllowed = $inboundB2B.usersAndGroups.accessType
        $unrestricted = $inboundAllowed -eq 'allowed' -or $null -eq $inboundAllowed

        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-005: B2B Collaboration Settings' `
            -Status    (if ($unrestricted) { 'Warning' } else { 'Pass' }) `
            -Detail    "Cross-tenant inbound B2B access: $inboundAllowed. Partner-specific policies configured: $partnerCount. Unrestricted inbound allows any external user to be invited." `
            -Recommendation 'Review cross-tenant access policy defaults. Consider restricting inbound B2B to specific partner tenants or requiring MFA/compliant devices from external users.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-overview' `
            -Category  'Identity' `
            -Severity  'Medium' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'IAM-005: B2B Collaboration Settings' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-overview' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    return $results
}
