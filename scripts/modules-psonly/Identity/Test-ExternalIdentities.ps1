#Requires -Version 7.0

<#
.SYNOPSIS
    Checks Entra ID external identity and B2B/B2B Direct Connect configuration. PS-only variant.

.DESCRIPTION
    Evaluates cross-tenant access policy defaults, configured identity providers,
    partner-specific cross-tenant policies, and B2B Direct Connect outbound settings.
    Checks: EXT-001 through EXT-004.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/Identity/Test-ExternalIdentities.ps1

    CHANGES vs. Graph variant:
        EXT-001: Invoke-MgGraphRequest GET /crossTenantAccessPolicy/default
                 -> Get-MgPolicyCrossTenantAccessPolicyDefault
        EXT-002: Invoke-MgGraphRequest GET /identityProviders
                 -> No confirmed typed cmdlet for identityProviders in mapping table.
                    Falls back to INFO result with reference to Graph variant.
        EXT-003: Invoke-MgGraphRequest GET /crossTenantAccessPolicy/partners
                 -> Get-MgPolicyCrossTenantAccessPolicyPartner -All
        EXT-004: Invoke-MgGraphRequest GET /crossTenantAccessPolicy/default (second call)
                 -> Get-MgPolicyCrossTenantAccessPolicyDefault (result reused from EXT-001)

.NOTES
    Required connection  : Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All"
    Required scopes      : Policy.Read.All, Directory.Read.All
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Identity.SignIns

    License: E3 minimum; cross-tenant access policies available on all editions.
    Assumes New-AssessmentResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-ExternalIdentities {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Retrieve default cross-tenant access policy once, reused by EXT-001 and EXT-004
    $defaultPolicy = $null
    try {
        $defaultPolicy = Get-MgPolicyCrossTenantAccessPolicyDefault -ErrorAction Stop
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'EXT-000: Cross-Tenant Policy Retrieval' `
            -Status    'Info' `
            -Detail    "Could not retrieve cross-tenant access policy default. EXT-001 and EXT-004 skipped. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All and reconnect: Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-overview' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # EXT-001: Cross-tenant default inbound trust settings
    if ($defaultPolicy) {
        try {
            $inboundB2B        = $defaultPolicy.B2bCollaborationInbound
            $inboundTrust      = $defaultPolicy.InboundTrust
            $mfaTrusted        = $inboundTrust.IsMfaAccepted
            $compliantTrusted  = $inboundTrust.IsCompliantDeviceAccepted
            $hybridJoinTrusted = $inboundTrust.IsHybridAzureAdJoinedDeviceAccepted

            $inboundAccessType = $inboundB2B.UsersAndGroups.AccessType
            $unrestricted = $inboundAccessType -eq 'allowed' -or $null -eq $inboundAccessType

            $results.Add((New-AssessmentResult `
                -CheckName 'EXT-001: Cross-Tenant Inbound B2B Trust Settings' `
                -Status    (if ($unrestricted) { 'Warning' } else { 'Pass' }) `
                -Detail    "Inbound B2B access: $inboundAccessType. MFA from partner trusted: $mfaTrusted. Compliant device trusted: $compliantTrusted. Hybrid-joined device trusted: $hybridJoinTrusted." `
                -Recommendation 'Review cross-tenant access defaults. Consider configuring inbound trust settings to require MFA/compliant devices from external users, or restrict inbound access to specific partner tenants.' `
                -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration' `
                -Category  'Identity' `
                -Severity  (if ($unrestricted) { 'Medium' } else { 'Info' }) `
                -MitreId   'T1078' `
                -MitreTactic 'InitialAccess' `
                -CisControl ''))
        }
        catch {
            $results.Add((New-AssessmentResult `
                -CheckName 'EXT-001: Cross-Tenant Inbound Trust' `
                -Status    'Info' `
                -Detail    "Check failed: $_" `
                -Recommendation 'Verify Policy.Read.All scope.' `
                -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration' `
                -Category  'Identity' `
                -Severity  'Info'))
        }
    }

    # EXT-002: External identity providers configured
    # No typed cmdlet confirmed in mapping table for /identityProviders.
    # Emitting INFO result and directing to Graph variant or portal.
    $results.Add((New-AssessmentResult `
        -CheckName 'EXT-002: External Identity Providers' `
        -Status    'Info' `
        -Detail    "EXT-002 is not available in PS-only mode: no typed SDK cmdlet exists for /identityProviders in the confirmed mapping table. To check configured social/external identity providers, use the Graph variant (scripts/modules/Identity/Test-ExternalIdentities.ps1) or inspect Entra ID > External Identities > All identity providers in the portal." `
        -Recommendation 'Review configured identity providers in the Entra admin center. Remove unused providers. For B2B, prefer Email OTP or Microsoft Account over social IdPs.' `
        -Reference 'https://learn.microsoft.com/entra/external-id/identity-providers' `
        -Category  'Identity' `
        -Severity  'Info' `
        -CisControl ''))

    # EXT-003: Partner-specific cross-tenant access policies with unrestricted inbound
    try {
        $partners = Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction Stop
        $partnerList  = @($partners)
        $partnerCount = $partnerList.Count

        $unrestrictedPartners = @()
        foreach ($partner in $partnerList) {
            $inboundB2B    = $partner.B2bCollaborationInbound
            $inboundAccess = $inboundB2B.UsersAndGroups.AccessType
            if ($inboundAccess -eq 'allowed' -or $null -eq $inboundB2B) {
                $unrestrictedPartners += $partner.TenantId
            }
        }

        $results.Add((New-AssessmentResult `
            -CheckName 'EXT-003: Partner Cross-Tenant Access Policies' `
            -Status    (if ($unrestrictedPartners.Count -gt 0) { 'Warning' } else { 'Pass' }) `
            -Detail    "$partnerCount partner-specific policies configured. Partners with unrestricted inbound B2B: $($unrestrictedPartners.Count). Tenant IDs: $($unrestrictedPartners -join ', ')" `
            -Recommendation 'For each partner policy, specify which users/groups are allowed inbound. Avoid blanket allow rules. Configure inbound MFA/device trust requirements per partner.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration' `
            -Category  'Identity' `
            -Severity  (if ($unrestrictedPartners.Count -gt 0) { 'Medium' } else { 'Info' }) `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'EXT-003: Partner Cross-Tenant Policies' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # EXT-004: B2B Direct Connect outbound settings (reuses $defaultPolicy from above)
    if ($defaultPolicy) {
        try {
            $b2bDirectConnectOutbound = $defaultPolicy.B2bDirectConnectOutbound
            $outboundAccessType = $b2bDirectConnectOutbound.UsersAndGroups.AccessType
            $unrestricted = $outboundAccessType -eq 'allowed' -or $null -eq $outboundAccessType

            $results.Add((New-AssessmentResult `
                -CheckName 'EXT-004: B2B Direct Connect Outbound' `
                -Status    (if ($unrestricted) { 'Fail' } else { 'Pass' }) `
                -Detail    "B2B Direct Connect outbound access type: $outboundAccessType. Unrestricted outbound allows your users to join external Teams shared channels and share data with other tenants." `
                -Recommendation 'Restrict B2B Direct Connect outbound access. If not actively using Teams Connect shared channels, set outbound B2B Direct Connect to blocked. If in use, restrict to specific partner tenants.' `
                -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-direct-connect' `
                -Category  'Identity' `
                -Severity  (if ($unrestricted) { 'High' } else { 'Info' }) `
                -MitreId   'T1537' `
                -MitreTactic 'Exfiltration' `
                -CisControl ''))
        }
        catch {
            $results.Add((New-AssessmentResult `
                -CheckName 'EXT-004: B2B Direct Connect Outbound' `
                -Status    'Info' `
                -Detail    "Check failed: $_" `
                -Recommendation 'Verify Policy.Read.All scope.' `
                -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-direct-connect' `
                -Category  'Identity' `
                -Severity  'Info'))
        }
    }

    return $results
}
