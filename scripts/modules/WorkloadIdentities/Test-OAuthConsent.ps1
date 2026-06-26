#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits OAuth 2.0 consent policies, tenant-wide grants, and per-user consent posture.

.DESCRIPTION
    Test-OAuthConsent evaluates the tenant's OAuth consent configuration: whether users can
    self-consent to applications, whether the admin consent workflow is enabled as a fallback,
    the inventory of tenant-wide delegated grants, per-user grants for sensitive scopes, and
    the publisher verification status of apps with admin consent.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

.NOTES
    Required Graph Permissions : Policy.Read.All, Application.Read.All
    License Required            : E3 minimum
    Module                      : Microsoft.Graph.Authentication (uses Invoke-MgGraphRequest)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        OAU-001  User consent policy (can users self-consent?)
        OAU-002  Admin consent workflow enabled
        OAU-003  Tenant-wide OAuth grant inventory
        OAU-004  Per-user consents with sensitive scopes
        OAU-005  Publisher verification of apps with admin consent
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/WorkloadIdentities/Test-OAuthConsent.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-OAuthConsent {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

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
    # -------------------------------------------------------------------------
    try {
        $authPolicyResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' `
            -ErrorAction Stop

        $permGrantPolicies = @($authPolicyResp.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $canCreateApps     = $authPolicyResp.defaultUserRolePermissions.allowedToCreateApps

        # Determine consent policy level:
        # - managePermissionGrantsForSelf.microsoft-user-default-legacy  = users can consent to any app
        # - managePermissionGrantsForSelf.microsoft-user-default-low      = verified publishers only
        # - empty / admin-only policy                                      = admin consent required
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
            $oau001Detail = "User consent policy: users cannot self-consent to applications. Admin approval is required for all consent grants. Policy: $($policyDetail -or 'none (admin-only)')"
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
            -Recommendation 'Grant Policy.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # OAU-002: Admin consent workflow configured
    # -------------------------------------------------------------------------
    try {
        $consentWorkflowResp = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/beta/policies/adminConsentRequestPolicy' `
            -ErrorAction Stop

        $workflowEnabled = $consentWorkflowResp.isEnabled -eq $true

        if ($workflowEnabled) {
            $reviewers      = @($consentWorkflowResp.version)
            $oau002Status   = 'PASS'
            $oau002Detail   = "Admin consent workflow is enabled. Users who are blocked from self-consenting will see an option to request admin approval rather than a hard denial."
        }
        else {
            $oau002Status = 'HIGH'
            $oau002Detail = "Admin consent workflow is NOT enabled. When user consent is blocked, users receive no option to request access — this forces admins to grant consent manually or users to work around restrictions."
        }

        $results.Add((New-CheckResult `
            -CheckId 'OAU-002' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: Admin Consent Workflow' `
            -Status $oau002Status `
            -Detail $oau002Detail `
            -Recommendation 'Enable the admin consent workflow in Entra ID > Enterprise apps > Consent and permissions. Assign reviewers and set notification settings so consent requests are processed promptly.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'OAU-002' `
            -Category 'WorkloadIdentities' `
            -Name 'OAuth Consent: Admin Consent Workflow' `
            -Status 'INFO' `
            -Detail "Check skipped: beta endpoint not accessible or insufficient permissions. Error: $_" `
            -Recommendation 'Verify access to the beta/policies/adminConsentRequestPolicy endpoint and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/configure-admin-consent-workflow' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # OAU-003: All tenant-wide OAuth consents inventory
    # -------------------------------------------------------------------------
    $microsoftTenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'

    try {
        $allGrantsUri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=consentType eq ''AllPrincipals''&$top=999'
        $allGrants    = [System.Collections.Generic.List[hashtable]]::new()
        do {
            $grantsPage = Invoke-MgGraphRequest -Method GET -Uri $allGrantsUri -ErrorAction Stop
            foreach ($g in $grantsPage.value) { $allGrants.Add($g) }
            $allGrantsUri = $grantsPage.'@odata.nextLink'
        } while ($allGrantsUri)

        $dangerousGrants = [System.Collections.Generic.List[string]]::new()

        foreach ($grant in $allGrants) {
            $scopes = $grant.scope -split ' '
            $matched = $scopes | Where-Object { $_ -in $sensitiveDelegatedScopes }
            if (-not $matched) { continue }

            # Resolve SP to check if it's a Microsoft app
            try {
                $spDetail = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.clientId)?`$select=displayName,appOwnerOrganizationId,verifiedPublisher" `
                    -ErrorAction Stop
                if ($spDetail.appOwnerOrganizationId -eq $microsoftTenantId) { continue }
                $pubVerified = if ($spDetail.verifiedPublisher.displayName) { $spDetail.verifiedPublisher.displayName } else { 'UNVERIFIED' }
                $dangerousGrants.Add("$($spDetail.displayName) [publisher: $pubVerified, scopes: $($matched -join ', ')]")
            }
            catch {
                $dangerousGrants.Add("$($grant.clientId) [scopes: $($matched -join ', ')]")
            }
        }

        if ($dangerousGrants.Count -gt 0) {
            $results.Add((New-CheckResult `
                -CheckId 'OAU-003' `
                -Category 'WorkloadIdentities' `
                -Name 'OAuth Consent: Tenant-Wide Sensitive Grants (Non-Microsoft)' `
                -Status 'HIGH' `
                -Detail "Found $($dangerousGrants.Count) tenant-wide (AllPrincipals) OAuth grant(s) for sensitive scopes on non-Microsoft apps. Total AllPrincipals grants: $($allGrants.Count)." `
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
                -Detail "Total tenant-wide (AllPrincipals) OAuth grants: $($allGrants.Count). No non-Microsoft apps with sensitive scopes found." `
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
    # -------------------------------------------------------------------------
    try {
        $perUserGrantsUri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=consentType eq ''Principal''&$top=999'
        $perUserGrants    = [System.Collections.Generic.List[hashtable]]::new()
        do {
            $puPage = Invoke-MgGraphRequest -Method GET -Uri $perUserGrantsUri -ErrorAction Stop
            foreach ($g in $puPage.value) { $perUserGrants.Add($g) }
            $perUserGrantsUri = $puPage.'@odata.nextLink'
        } while ($perUserGrantsUri)

        # Aggregate by clientId: count how many users granted sensitive scopes to each app
        $appUserCounts = @{}
        $appNames      = @{}

        foreach ($grant in $perUserGrants) {
            $scopes  = $grant.scope -split ' '
            $matched = $scopes | Where-Object { $_ -in $sensitiveDelegatedScopes }
            if (-not $matched) { continue }

            $clientId = $grant.clientId
            if (-not $appUserCounts.ContainsKey($clientId)) {
                $appUserCounts[$clientId] = 0
                # Resolve app name once per clientId
                try {
                    $spLookup = Invoke-MgGraphRequest -Method GET `
                        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$clientId`?`$select=displayName,appOwnerOrganizationId" `
                        -ErrorAction Stop
                    if ($spLookup.appOwnerOrganizationId -eq $microsoftTenantId) {
                        $appUserCounts[$clientId] = -1  # mark as Microsoft, skip
                    }
                    else {
                        $appNames[$clientId] = $spLookup.displayName
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

        # Build list of third-party apps where >= 5 users granted sensitive scopes
        $widespreadGrants = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $appUserCounts.Keys) {
            $count = $appUserCounts[$key]
            if ($count -ge 5) {
                $name = if ($appNames.ContainsKey($key)) { $appNames[$key] } else { $key }
                $widespreadGrants.Add("$name [$count users with sensitive scope consent]")
            }
        }

        $oau004Status = if ($widespreadGrants.Count -gt 0) { 'HIGH' } else { 'LOW' }
        $oau004Detail = "Total per-user (Principal) OAuth grants: $($perUserGrants.Count)."
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
    # -------------------------------------------------------------------------
    try {
        $unverifiedApps = [System.Collections.Generic.List[string]]::new()

        # Retrieve all AllPrincipals grants to find admin-consented apps
        $acGrantsUri = 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$filter=consentType eq ''AllPrincipals''&$top=999'
        $acClientIds = [System.Collections.Generic.HashSet[string]]::new()
        do {
            $acPage = Invoke-MgGraphRequest -Method GET -Uri $acGrantsUri -ErrorAction Stop
            foreach ($g in $acPage.value) { [void]$acClientIds.Add($g.clientId) }
            $acGrantsUri = $acPage.'@odata.nextLink'
        } while ($acGrantsUri)

        foreach ($clientId in $acClientIds) {
            try {
                $spVer = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$clientId`?`$select=displayName,appOwnerOrganizationId,verifiedPublisher" `
                    -ErrorAction Stop

                # Skip Microsoft first-party apps
                if ($spVer.appOwnerOrganizationId -eq $microsoftTenantId) { continue }

                $isVerified = $spVer.verifiedPublisher -and $spVer.verifiedPublisher.displayName
                if (-not $isVerified) {
                    $unverifiedApps.Add($spVer.displayName)
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
            -Detail "Check skipped: insufficient permissions or API error. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity-platform/publisher-verification-overview' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
