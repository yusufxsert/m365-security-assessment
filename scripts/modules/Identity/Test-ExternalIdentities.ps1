#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Checks Entra ID external identity and B2B/B2B Direct Connect configuration.
.DESCRIPTION
    Evaluates cross-tenant access policy defaults, configured identity providers,
    partner-specific cross-tenant policies, and B2B Direct Connect outbound settings.
    Checks: EXT-001 through EXT-004.
.NOTES
    Required Permissions:
        Policy.Read.All
        Directory.Read.All
    License: E3 minimum; cross-tenant access policies available on all editions
#>

function Test-ExternalIdentities {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # EXT-001: Cross-tenant default inbound trust settings
    try {
        $defaultPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' `
            -ErrorAction Stop

        $inboundB2B         = $defaultPolicy.b2bCollaborationInbound
        $inboundTrust       = $defaultPolicy.inboundTrust
        $mfaTrusted         = $inboundTrust.isMfaAccepted
        $compliantTrusted   = $inboundTrust.isCompliantDeviceAccepted
        $hybridJoinTrusted  = $inboundTrust.isHybridAzureADJoinedDeviceAccepted

        $inboundAccessType  = $inboundB2B.usersAndGroups.accessType

        # If inbound is unrestricted AND MFA from external tenant is not trusted (means our CA won't accept their MFA)
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
            -Detail    "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # EXT-002: External identity providers configured
    try {
        $idProviders = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identityProviders' `
            -ErrorAction Stop

        $providerList = $idProviders.value
        $providerCount = if ($providerList) { $providerList.Count } else { 0 }
        $providerNames = if ($providerList) {
            ($providerList | ForEach-Object { $_.displayName }) -join ', '
        } else { 'None' }

        $results.Add((New-AssessmentResult `
            -CheckName 'EXT-002: External Identity Providers' `
            -Status    'Info' `
            -Detail    "$providerCount external identity provider(s) configured: $providerNames. Social/external IdPs allow B2B users to authenticate with their own credentials." `
            -Recommendation 'Review configured identity providers. Remove any unused providers. For B2B scenarios, prefer Email OTP or Microsoft Account over social IdPs to maintain control.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/identity-providers' `
            -Category  'Identity' `
            -Severity  'Info' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'EXT-002: External Identity Providers' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: IdentityProvider.Read.All. Error: $_" `
            -Recommendation 'Grant IdentityProvider.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/identity-providers' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # EXT-003: Partner-specific cross-tenant access policies with unrestricted inbound trust
    try {
        $partners = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners' `
            -ErrorAction Stop

        $partnerList = $partners.value
        $partnerCount = if ($partnerList) { $partnerList.Count } else { 0 }

        $unrestrictedPartners = @()
        foreach ($partner in $partnerList) {
            $tenantId   = $partner.tenantId
            $inboundB2B = $partner.b2bCollaborationInbound
            $trust      = $partner.inboundTrust

            # If b2bCollaborationInbound is null or usersAndGroups.accessType = 'allowed' with no specific user filter, flag it
            $inboundAccess = $inboundB2B.usersAndGroups.accessType
            if ($inboundAccess -eq 'allowed' -or $null -eq $inboundB2B) {
                $unrestrictedPartners += $tenantId
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
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-collaboration' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # EXT-004: B2B Direct Connect outbound settings
    try {
        $defaultPolicy = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default' `
            -ErrorAction Stop

        $b2bDirectConnectOutbound = $defaultPolicy.b2bDirectConnectOutbound
        $outboundAccessType = $b2bDirectConnectOutbound.usersAndGroups.accessType

        # B2B Direct Connect (Teams Connect shared channels) outbound unrestricted means
        # your users can be added to external Teams channels without approval
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
            -Detail    "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/external-id/cross-tenant-access-settings-b2b-direct-connect' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    return $results
}
