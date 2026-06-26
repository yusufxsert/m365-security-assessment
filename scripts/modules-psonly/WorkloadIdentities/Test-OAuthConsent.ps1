#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Audits OAuth 2.0 consent policies, tenant-wide grants, and per-user consent posture.
    PS-only variant.

.DESCRIPTION
    Test-OAuthConsent evaluates the tenant's OAuth consent configuration: whether users can
    self-consent to applications, whether the admin consent workflow is enabled as a fallback,
    the inventory of tenant-wide delegated grants, per-user grants for sensitive scopes, and
    the publisher verification status of apps with admin consent.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/WorkloadIdentities/Test-OAuthConsent.ps1

    CHANGES vs. Graph variant:
        OAU-001: Invoke-MgGraphRequest GET /policies/authorizationPolicy
                 -> Get-MgPolicyAuthorizationPolicy
        OAU-002: Invoke-MgGraphRequest GET beta/policies/adminConsentRequestPolicy
                 No confirmed typed PS cmdlet for adminConsentRequestPolicy in mapping table.
                 Falls back to INFO result with reference to portal and Graph variant.
        OAU-003: Invoke-MgGraphRequest paged GET /oauth2PermissionGrants?$filter=consentType eq 'AllPrincipals'
                 -> Get-MgOauth2PermissionGrant -Filter "consentType eq 'AllPrincipals'" -All
                 SP detail (verifiedPublisher, appOwnerOrganizationId) lookup:
                 -> Get-MgServicePrincipal -Filter "id eq '{id}'" -Property '...'
                    (Note: filter on id not directly supported; use Get-MgServicePrincipal -ServicePrincipalId {id})
        OAU-004: Invoke-MgGraphRequest paged GET /oauth2PermissionGrants?$filter=consentType eq 'Principal'
                 -> Get-MgOauth2PermissionGrant -Filter "consentType eq 'Principal'" -All
        OAU-005: Re-uses AllPrincipals grants already retrieved in OAU-003.

.NOTES
    Required connection  : Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All","Directory.Read.All"
    Required scopes      : Policy.Read.All, Application.Read.All, Directory.Read.All
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Applications
                           Microsoft.Graph.Identity.SignIns

    License Required            : E3 minimum
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        OAU-001  User consent policy (can users self-consent?)
        OAU-002  Admin consent workflow enabled [INFO stub - beta only]
        OAU-003  Tenant-wide OAuth grant inventory
        OAU-004  Per-user consents with sensitive scopes
        OAU-005  Publisher verification of apps with admin consent
#>

function Test-OAuthConsent {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'

    $sensitiveDelegatedScopes = @(
        'Mail.ReadWrite', 'Mail.Read', 'Mail.Send',
        'Files.ReadWrite.All', 'Files.Read.All',
        'Contacts.ReadWrite', 'Contacts.Read',
        'Calendars.ReadWrite', 'Calendars.Read',
        'User.ReadWrite.All', 'Directory.ReadWrite.All',
        'MailboxSettings.ReadWrite', 'Chat.Read',
        'ChannelMessage.Read.All', 'People.Read.All'
    )

    # -------------------------------------------------------------------------
    # OAU-001: User consent policy
    # Uses Get-MgPolicyAuthorizationPolicy
    # -------------------------------------------------------------------------
    try {
        $authPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop

        $permGrantPolicies = @($authPolicy.DefaultUserRolePermissions.PermissionGrantPoliciesAssigned)
        $canCreateApps     = $authPolicy.DefaultUserRolePermissions.AllowedToCreateApps

        $policyDetail = $permGrantPolicies -join ', '

        if ($permGrantPolicies -contains 'managePermissionGrantsForSelf.microsoft-user-default-legacy') {
            $oau001Status = 'CRITICAL'
            $oau001Detail = "User consent policy: users can consent to any application (policy: $policyDetail). This allows any app — including malicious OAuth phishing apps — to gain access to user data without admin review."
        }
        elseif ($permGrantPolicies | Where-Object { $_ -like '*microsoft-user-default-low*' }) {
            $oau001Status = 'HIGH'
            $oau001Detail = "User consent policy: users can consent to apps from verified publishers only (policy: $policyDetail). Publisher verification provides some protection but is not equivalent to admin review."
        }
        elseif ($permGrantPolicies.Count -eq 0 -or $permGrantPolicies -contains 'managePermissionGrantsForSelf.0') {
            $oau001Status = 'PASS'
            $oau001Detail = "User consent policy: users cannot self-consent to applications. Admin approval is required for all consent grants. Policy: $(if ($policyDetail) { $policyDetail } else { 'none (admin-only)' })"
        }
        else {
            $oau001Status = 'MEDIUM'
            $oau001Detail = "User consent policy is configured but unclear. Assigned policies: $policyDetail. Manual review recommended."
        }

        if ($canCreateApps) {
            $oau001Detail += ' Note: Users are allowed to create app registrations — this is an additional risk vector.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'OAU-001' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: User Consent Policy' `
            -Status $oau001Status `
            -Detail $oau001Detail `
            -Recommendation 'Set user consent to "Allow user consent for apps from verified publishers, for selected permissions (low impact)" at most, or disable user consent entirely and require admin approval via the consent workflow.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'OAU-001' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: User Consent Policy' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All and reconnect: Connect-MgGraph -Scopes "Policy.Read.All","Application.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # OAU-002: Admin consent workflow configured
    # adminConsentRequestPolicy is beta-only; no confirmed typed PS cmdlet in mapping table.
    # Emitting INFO stub.
    # -------------------------------------------------------------------------
    $results.Add((New-CheckResult `
        -CheckId 'OAU-002' `
        -Category 'WorkloadIdentities' `
        -Name 'OAuth Consent: Admin Consent Workflow' `
        -Status 'INFO' `
        -Detail "OAU-002 is not available in PS-only mode: the adminConsentRequestPolicy endpoint is beta-only and has no confirmed typed PS cmdlet in the mapping table. To check the admin consent workflow, use the Graph variant (scripts/modules/WorkloadIdentities/Test-OAuthConsent.ps1) or review: Entra admin center > Enterprise applications > Consent and permissions > Admin consent settings." `
        -Recommendation 'Enable the admin consent workflow in Entra admin center > Enterprise applications > Consent and permissions. Assign reviewers so consent requests are processed promptly.' `
        -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
        -CISControl '' `
        -SC300Domain 'Workload Identities' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # OAU-003: All tenant-wide OAuth consents inventory
    # Uses Get-MgOauth2PermissionGrant -Filter "consentType eq 'AllPrincipals'" -All
    # SP detail lookup uses Get-MgServicePrincipal -ServicePrincipalId {id}
    # -------------------------------------------------------------------------
    $allPrincipalGrants = $null
    try {
        $allPrincipalGrants = Get-MgOauth2PermissionGrant -Filter "consentType eq 'AllPrincipals'" -All -ErrorAction Stop
        $allGrantsCount = @($allPrincipalGrants).Count

        $dangerousGrants = [System.Collections.Generic.List[string]]::new()

        foreach ($grant in $allPrincipalGrants) {
            $scopes  = $grant.Scope -split ' '
            $matched = $scopes | Where-Object { $_ -in $sensitiveDelegatedScopes }
            if (-not $matched) { continue }

            try {
                $spDetail = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId `
                    -Property 'displayName,appOwnerOrganizationId,verifiedPublisher' -ErrorAction Stop
                if ($spDetail.AppOwnerOrganizationId -eq $microsoftTenantId) { continue }
                $pubVerified = if ($spDetail.VerifiedPublisher.DisplayName) { $spDetail.VerifiedPublisher.DisplayName } else { 'UNVERIFIED' }
                $dangerousGrants.Add("$($spDetail.DisplayName) [publisher: $pubVerified, scopes: $($matched -join ', ')]")
            }
            catch {
                $dangerousGrants.Add("$($grant.ClientId) [scopes: $($matched -join ', ')]")
            }
        }

        if ($dangerousGrants.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'OAU-003' `
                -Category 'WorkloadIdentities' `
                -Name 'OAuth Consent: Tenant-Wide Sensitive Grants (Non-Microsoft)' `
                -Status 'HIGH' `
                -Detail "Found $($dangerousGrants.Count) tenant-wide (AllPrincipals) OAuth grant(s) for sensitive scopes on non-Microsoft apps. Total AllPrincipals grants: $allGrantsCount." `
                -Recommendation 'Review and revoke grants not explicitly approved. Each grant allows the app to act on behalf of any user in the tenant for the granted scopes.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
                -CISControl 'CIS M365 1.6' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects $dangerousGrants.ToArray()))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'OAU-003' `
                -Category 'WorkloadIdentities' `
                -Name 'OAuth Consent: Tenant-Wide Grant Inventory' `
                -Status 'INFO' `
                -Detail "Total tenant-wide (AllPrincipals) OAuth grants: $allGrantsCount. No non-Microsoft apps with sensitive scopes found." `
                -Recommendation 'Periodically review all AllPrincipals grants. Even non-sensitive scopes should be regularly audited for necessity.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
                -CISControl 'CIS M365 1.6' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'OAU-003' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: Tenant-Wide Grant Inventory' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # OAU-004: Per-user consents with sensitive scopes to third-party apps
    # Uses Get-MgOauth2PermissionGrant -Filter "consentType eq 'Principal'" -All
    # -------------------------------------------------------------------------
    try {
        $perUserGrants = Get-MgOauth2PermissionGrant -Filter "consentType eq 'Principal'" -All -ErrorAction Stop

        $appUserCounts = @{}
        $appNames      = @{}

        foreach ($grant in $perUserGrants) {
            $scopes  = $grant.Scope -split ' '
            $matched = $scopes | Where-Object { $_ -in $sensitiveDelegatedScopes }
            if (-not $matched) { continue }

            $clientId = $grant.ClientId
            if (-not $appUserCounts.ContainsKey($clientId)) {
                $appUserCounts[$clientId] = 0
                try {
                    $spLookup = Get-MgServicePrincipal -ServicePrincipalId $clientId `
                        -Property 'displayName,appOwnerOrganizationId' -ErrorAction Stop
                    if ($spLookup.AppOwnerOrganizationId -eq $microsoftTenantId) {
                        $appUserCounts[$clientId] = -1
                    }
                    else {
                        $appNames[$clientId] = $spLookup.DisplayName
                    }
                }
                catch {
                    $appNames[$clientId] = $clientId
                }
            }
            if ($appUserCounts[$clientId] -ge 0) {
                $appUserCounts[$clientId]++
            }
        }

        $widespreadGrants = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $appUserCounts.Keys) {
            $count = $appUserCounts[$key]
            if ($count -ge 5) {
                $name = if ($appNames.ContainsKey($key)) { $appNames[$key] } else { $key }
                $widespreadGrants.Add("$name [$count users with sensitive scope consent]")
            }
        }

        $oau004Status = if ($widespreadGrants.Count -gt 0) { 'HIGH' } else { 'LOW' }
        $oau004Detail = "Total per-user (Principal) OAuth grants: $(@($perUserGrants).Count)."
        if ($widespreadGrants.Count -gt 0) {
            $oau004Detail += " Found $($widespreadGrants.Count) third-party app(s) where 5+ users have consented sensitive scopes. This could indicate OAuth phishing or uncontrolled broad adoption."
        }
        else {
            $oau004Detail += ' No third-party apps found with 5 or more users having sensitive scope consents.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'OAU-004' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: Per-User Sensitive Scope Consents (Third-Party Apps)' `
            -Status $oau004Status `
            -Detail $oau004Detail `
            -Recommendation 'Review apps with widespread per-user consent for sensitive scopes. If the app is sanctioned, convert individual consents to a single admin-consent grant for centralized control. If not sanctioned, revoke all grants and block the app.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $widespreadGrants.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'OAU-004' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: Per-User Sensitive Scope Consents' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/manage-consent-requests' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # OAU-005: Publisher verification of apps with admin consent
    # Re-uses $allPrincipalGrants from OAU-003. Looks up each SP via
    # Get-MgServicePrincipal -ServicePrincipalId {id} -Property '...'
    # -------------------------------------------------------------------------
    if ($allPrincipalGrants) {
        try {
            $acClientIds = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($g in $allPrincipalGrants) { [void]$acClientIds.Add($g.ClientId) }

            $unverifiedApps = [System.Collections.Generic.List[string]]::new()

            foreach ($clientId in $acClientIds) {
                try {
                    $spVer = Get-MgServicePrincipal -ServicePrincipalId $clientId `
                        -Property 'displayName,appOwnerOrganizationId,verifiedPublisher' -ErrorAction Stop

                    if ($spVer.AppOwnerOrganizationId -eq $microsoftTenantId) { continue }

                    $isVerified = $spVer.VerifiedPublisher -and $spVer.VerifiedPublisher.DisplayName
                    if (-not $isVerified) {
                        $unverifiedApps.Add($spVer.DisplayName)
                    }
                }
                catch {
                    Write-Verbose "OAU-005: Could not check publisher for $clientId: $_"
                }
            }

            if ($unverifiedApps.Count -gt 0) {
                $results.Add((New-CheckResult `
                    -CheckId 'OAU-005' `
                    -Category 'WorkloadIdentities' `
                    -Name 'OAuth Consent: Unverified Publisher Apps With Admin Consent' `
                    -Status 'MEDIUM' `
                    -Detail "Found $($unverifiedApps.Count) non-Microsoft app(s) with tenant-wide admin consent that have NOT completed Microsoft publisher verification. Unverified publishers have not confirmed their identity with Microsoft." `
                    -Recommendation 'Require publisher verification for apps used in the tenant. For unverified apps with admin consent, evaluate whether the app is truly necessary and request the vendor to complete publisher verification.' `
                    -Reference 'https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview' `
                    -CISControl '' `
                    -SC300Domain 'Workload Identities' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects $unverifiedApps.ToArray()))
            }
            else {
                $results.Add((New-CheckResult `
                    -CheckId 'OAU-005' `
                    -Category 'WorkloadIdentities' `
                    -Name 'OAuth Consent: Publisher Verification for Admin-Consented Apps' `
                    -Status 'PASS' `
                    -Detail 'All non-Microsoft apps with tenant-wide admin consent have completed Microsoft publisher verification.' `
                    -Recommendation 'Maintain publisher verification requirement for all new enterprise apps.' `
                    -Reference 'https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview' `
                    -CISControl '' `
                    -SC300Domain 'Workload Identities' `
                    -LicenseRequired 'E3' `
                    -AffectedObjects @()))
            }
        }
        catch {
            $results.Add((New-CheckResult `
                -CheckId 'OAU-005' `
                -Category 'WorkloadIdentities' `
                -Name 'OAuth Consent: Publisher Verification' `
                -Status 'INFO' `
                -Detail "Check skipped: error during SP publisher lookup. Required: Application.Read.All. Error: $_" `
                -Recommendation 'Grant Application.Read.All and retry.' `
                -Reference 'https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview' `
                -CISControl '' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'OAU-005' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: Publisher Verification' `
            -Status 'INFO' `
            -Detail "OAU-005 skipped: OAU-003 did not retrieve grants (insufficient permissions or no AllPrincipals grants exist). Required: Application.Read.All." `
            -Recommendation 'Grant Application.Read.All and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
