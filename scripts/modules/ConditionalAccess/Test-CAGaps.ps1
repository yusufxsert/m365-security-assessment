#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Detects missing Conditional Access policy patterns (security gaps) in the tenant.

.DESCRIPTION
    Test-CAGaps evaluates whether key CA policy patterns are implemented and enforced.
    It does NOT check policy quality — it checks absence. Each gap is reported with a
    severity that reflects real-world attack risk if the control is missing.

    Covered gaps:
      GAP-001  No MFA for all users
      GAP-002  No MFA for admins (Microsoft baseline)
      GAP-003  No legacy authentication block
      GAP-004  No device compliance requirement
      GAP-005  No block for high-risk sign-ins (E5)
      GAP-006  No block for high-risk users (E5)
      GAP-007  No CA policy for Azure/Admin portals
      GAP-008  No persistent browser session prevention
      GAP-009  No Terms of Use gate
      GAP-010  Break-glass account exclusion check

.NOTES
    Required Graph Permissions : Policy.Read.All
    License Required            : E3; GAP-005 and GAP-006 require E5 / Entra ID P2

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/ConditionalAccess/Test-CAGaps.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-CAGaps {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all CA policies once; abort gracefully on permission failure
    # -------------------------------------------------------------------------
    try {
        $policiesResponse = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250' `
            -ErrorAction Stop
        $allPolicies = $policiesResponse.value

        $nextLink = $policiesResponse.'@odata.nextLink'
        while ($nextLink) {
            $page        = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $allPolicies += $page.value
            $nextLink    = $page.'@odata.nextLink'
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'GAP-000' `
            -Category 'ConditionalAccess' `
            -Name 'CA Gap Analysis — Policy Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/overview' `
            -CISControl '' `
            -SC300Domain 'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $enabled = @($allPolicies | Where-Object { $_.state -eq 'enabled' })

    # -------------------------------------------------------------------------
    # Helper: check whether a policy's grantControls require MFA
    # -------------------------------------------------------------------------
    $requiresMfa = {
        param($policy)
        $policy.grantControls.builtInControls -contains 'mfa' -or
        $policy.grantControls.authenticationStrength -ne $null
    }

    # -------------------------------------------------------------------------
    # GAP-001: No MFA for all users
    # -------------------------------------------------------------------------
    $mfaAllUsers = @($enabled | Where-Object {
        $_.conditions.users.includeUsers -contains 'All' -and (& $requiresMfa $_)
    })

    $gap001Status = if ($mfaAllUsers.Count -gt 0) { 'PASS' } else { 'CRITICAL' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-001' `
        -Category 'ConditionalAccess' `
        -Name 'MFA for All Users' `
        -Status $gap001Status `
        -Detail ("Enabled CA policies requiring MFA for all users: $($mfaAllUsers.Count). " +
                 "$(if ($gap001Status -eq 'CRITICAL') { 'No policy enforces MFA for all users — credential-based attacks will succeed without secondary verification.' })") `
        -Recommendation 'Create a CA policy: All users → All cloud apps → Require MFA (or authentication strength). Exclude only break-glass accounts.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa' `
        -CISControl 'CIS M365 1.2.2' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-002: No MFA for admins
    # -------------------------------------------------------------------------
    # Policies that target at least one directory role AND require MFA
    $mfaAdmins = @($enabled | Where-Object {
        $_.conditions.users.includeRoles.Count -gt 0 -and (& $requiresMfa $_)
    })

    # Also accept policies that target a group AND have "admin" in the name as a weaker signal
    $gap002Status = if ($mfaAdmins.Count -gt 0) { 'PASS' } else { 'CRITICAL' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-002' `
        -Category 'ConditionalAccess' `
        -Name 'MFA for Admins (Microsoft Baseline)' `
        -Status $gap002Status `
        -Detail ("Enabled CA policies requiring MFA for specific directory roles: $($mfaAdmins.Count). " +
                 "$(if ($gap002Status -eq 'CRITICAL') { 'CRITICAL: No role-scoped MFA policy found. Note: if GAP-001 passes with an All-users MFA policy, this is addressed but explicit admin policies are still recommended.' })") `
        -Recommendation 'Create a CA policy targeting all privileged roles (Global Admin, Privileged Role Admin, etc.) requiring phishing-resistant MFA strength.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-mfa' `
        -CISControl 'CIS M365 1.2.1' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-003: No legacy authentication block
    # -------------------------------------------------------------------------
    $legacyBlock = @($enabled | Where-Object {
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
         $_.conditions.clientAppTypes -contains 'other') -and
        $_.grantControls.builtInControls -contains 'block'
    })

    $gap003Status = if ($legacyBlock.Count -gt 0) { 'PASS' } else { 'CRITICAL' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-003' `
        -Category 'ConditionalAccess' `
        -Name 'Legacy Authentication Blocked' `
        -Status $gap003Status `
        -Detail ("Enabled CA policies blocking legacy auth (EAS / other client types): $($legacyBlock.Count). " +
                 "$(if ($gap003Status -eq 'CRITICAL') { 'Legacy protocols bypass MFA entirely — password spray is trivially effective without this block.' })") `
        -Recommendation 'Create a CA policy: All users → All cloud apps → Client apps: Exchange ActiveSync + Other → Block access.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' `
        -CISControl 'CIS M365 1.2.3' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-004: No device compliance requirement
    # -------------------------------------------------------------------------
    $compliancePolicies = @($enabled | Where-Object {
        $_.grantControls.builtInControls -contains 'compliantDevice' -or
        $_.grantControls.builtInControls -contains 'domainJoinedDevice'
    })

    $gap004Status = if ($compliancePolicies.Count -gt 0) { 'PASS' } else { 'HIGH' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-004' `
        -Category 'ConditionalAccess' `
        -Name 'Device Compliance Requirement' `
        -Status $gap004Status `
        -Detail ("Enabled CA policies requiring compliant or Hybrid Azure AD joined device: $($compliancePolicies.Count). " +
                 "$(if ($gap004Status -eq 'HIGH') { 'No device compliance gate — unmanaged/non-compliant endpoints can access corporate data.' })") `
        -Recommendation 'Create a CA policy requiring compliantDevice or hybridAzureADJoined for access to corporate apps (at minimum Exchange Online and SharePoint).' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-all-users-device-compliance' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-005: No block for high-risk sign-ins (E5)
    # -------------------------------------------------------------------------
    $highRiskSignIn = @($enabled | Where-Object {
        $_.conditions.signInRiskLevels -contains 'high' -and
        ($_.grantControls.builtInControls -contains 'block' -or (& $requiresMfa $_))
    })

    $gap005Status = if ($highRiskSignIn.Count -gt 0) { 'PASS' } else { 'HIGH' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-005' `
        -Category 'ConditionalAccess' `
        -Name 'High-Risk Sign-In Policy' `
        -Status $gap005Status `
        -Detail ("Enabled CA policies acting on high sign-in risk: $($highRiskSignIn.Count). " +
                 "$(if ($gap005Status -eq 'HIGH') { 'High-risk sign-ins (anomalous token use, atypical travel, etc.) proceed without additional friction.' })") `
        -Recommendation 'Create a CA policy: All users → All cloud apps → Sign-in risk: High → Block (or require MFA). Requires Entra ID P2.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-006: No block for high-risk users (E5)
    # -------------------------------------------------------------------------
    $highRiskUser = @($enabled | Where-Object {
        $_.conditions.userRiskLevels -contains 'high' -and
        ($_.grantControls.builtInControls -contains 'block' -or
         $_.grantControls.builtInControls -contains 'passwordChange' -or
         (& $requiresMfa $_))
    })

    $gap006Status = if ($highRiskUser.Count -gt 0) { 'PASS' } else { 'HIGH' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-006' `
        -Category 'ConditionalAccess' `
        -Name 'High-Risk User Policy' `
        -Status $gap006Status `
        -Detail ("Enabled CA policies acting on high user risk: $($highRiskUser.Count). " +
                 "$(if ($gap006Status -eq 'HIGH') { 'Users flagged as high-risk (leaked credentials, confirmed compromise) can still authenticate freely.' })") `
        -Recommendation 'Create a CA policy: All users → All cloud apps → User risk: High → Block or require password change. Requires Entra ID P2.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-configure-risk-policies' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-007: No CA policy for Azure / Admin portals
    # -------------------------------------------------------------------------
    # Well-known app IDs for admin portals
    $adminPortalAppIds = @(
        '797f4846-ba00-4fd7-ba43-dac1f8f63013',  # Windows Azure Service Management API (Azure Portal)
        '00000003-0000-0ff1-ce00-000000000000',  # SharePoint (Admin Center)
        '00000002-0000-0ff1-ce00-000000000000',  # Exchange (Admin Center)
        'MicrosoftAdminPortals'                   # Graph enum value for all admin portals
    )

    $adminPortalPolicies = @($enabled | Where-Object {
        $apps = $_.conditions.applications.includeApplications
        $apps -contains 'All' -or
        ($apps | Where-Object { $adminPortalAppIds -contains $_ }) -or
        $apps -contains 'MicrosoftAdminPortals'
    })

    # Filter to those that actually add a control (MFA, compliant device, or block unless allowed)
    $adminPortalProtected = @($adminPortalPolicies | Where-Object {
        (& $requiresMfa $_) -or
        $_.grantControls.builtInControls -contains 'compliantDevice' -or
        $_.grantControls.builtInControls -contains 'block'
    })

    $gap007Status = if ($adminPortalProtected.Count -gt 0) { 'PASS' } else { 'HIGH' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-007' `
        -Category 'ConditionalAccess' `
        -Name 'Admin Portal Access Protection' `
        -Status $gap007Status `
        -Detail ("Enabled CA policies protecting Azure/Admin portal access: $($adminPortalProtected.Count). " +
                 "$(if ($gap007Status -eq 'HIGH') { 'Admins can reach the Azure Portal / M365 Admin Center without additional CA enforcement beyond basic MFA.' })") `
        -Recommendation 'Create a CA policy targeting MicrosoftAdminPortals and Azure Management app IDs requiring MFA strength or compliant device for all privileged roles.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-admin-phish-resistant-mfa' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-008: No persistent browser session prevention
    # -------------------------------------------------------------------------
    $persistentBrowserPolicies = @($enabled | Where-Object {
        $_.sessionControls.persistentBrowser -and
        $_.sessionControls.persistentBrowser.isEnabled -eq $true -and
        $_.sessionControls.persistentBrowser.mode -eq 'never'
    })

    $gap008Status = if ($persistentBrowserPolicies.Count -gt 0) { 'PASS' } else { 'MEDIUM' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-008' `
        -Category 'ConditionalAccess' `
        -Name 'Persistent Browser Session Prevention' `
        -Status $gap008Status `
        -Detail ("Enabled CA policies preventing persistent browser sessions: $($persistentBrowserPolicies.Count). " +
                 "$(if ($gap008Status -eq 'MEDIUM') { 'No policy prevents persistent sessions — users on unmanaged devices stay signed in indefinitely.' })") `
        -Recommendation 'Create a CA policy for unmanaged/non-compliant devices: persistent browser session = Never. Pair with sign-in frequency control.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-session-lifetime' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-009: No Terms of Use gate
    # -------------------------------------------------------------------------
    $touPolicies = @($enabled | Where-Object {
        $_.grantControls.termsOfUse.Count -gt 0
    })

    $gap009Status = if ($touPolicies.Count -gt 0) { 'PASS' } else { 'LOW' }
    $results.Add((New-CheckResult `
        -CheckId 'GAP-009' `
        -Category 'ConditionalAccess' `
        -Name 'Terms of Use Gate' `
        -Status $gap009Status `
        -Detail ("Enabled CA policies with Terms of Use grant control: $($touPolicies.Count). " +
                 "$(if ($gap009Status -eq 'LOW') { 'No Terms of Use configured — missed opportunity for compliance acknowledgment and audit trail.' })") `
        -Recommendation 'Create a Terms of Use document and attach it as a CA grant control for guest users or sensitive applications.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/terms-of-use' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # GAP-010: Break-glass accounts excluded from blocking policies
    # -------------------------------------------------------------------------
    # Blocking policies: those that block access or require device compliance
    $blockingPolicies = @($enabled | Where-Object {
        $_.grantControls.builtInControls -contains 'block' -or
        $_.grantControls.builtInControls -contains 'compliantDevice'
    })

    # Collect all exclusion IDs across blocking policies
    $allExcludedUsers  = @($blockingPolicies | ForEach-Object { $_.conditions.users.excludeUsers }  | Where-Object { $_ } | Sort-Object -Unique)
    $allExcludedGroups = @($blockingPolicies | ForEach-Object { $_.conditions.users.excludeGroups } | Where-Object { $_ } | Sort-Object -Unique)

    # Policies that block ALL users with no exclusions are dangerous for break-glass
    $noExclusionBlockPolicies = @($blockingPolicies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All' -and
        $_.conditions.users.excludeUsers.Count -eq 0 -and
        $_.conditions.users.excludeGroups.Count -eq 0
    })

    $gap010Status  = 'PASS'
    $gap010Detail  = "Enabled blocking policies: $($blockingPolicies.Count). " +
                     "Unique excluded user objects: $($allExcludedUsers.Count). " +
                     "Unique excluded group objects: $($allExcludedGroups.Count). "
    $gap010Objects = @()

    if ($noExclusionBlockPolicies.Count -gt 0) {
        $gap010Status  = 'MEDIUM'
        $gap010Objects = @($noExclusionBlockPolicies.displayName)
        $gap010Detail  += "Policies blocking all users with NO exclusion (break-glass lockout risk): $($noExclusionBlockPolicies.Count). " +
                          "Policy names: $($gap010Objects -join '; ')"
    }
    elseif ($allExcludedUsers.Count -eq 0 -and $allExcludedGroups.Count -eq 0 -and $blockingPolicies.Count -gt 0) {
        $gap010Status = 'MEDIUM'
        $gap010Detail += 'No excluded accounts found in any blocking policy — verify break-glass exclusion is in place.'
    }
    else {
        $gap010Detail += "Break-glass exclusions appear present in blocking policies."
    }

    $results.Add((New-CheckResult `
        -CheckId 'GAP-010' `
        -Category 'ConditionalAccess' `
        -Name 'Break-Glass Account CA Exclusion' `
        -Status $gap010Status `
        -Detail $gap010Detail `
        -Recommendation 'Maintain a dedicated break-glass group (containing 2 emergency access accounts) excluded from all blocking CA policies. Document and monitor its use.' `
        -Reference 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects $gap010Objects))

    return $results
}
