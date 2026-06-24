#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Inventories and evaluates all Conditional Access policies in the tenant.

.DESCRIPTION
    Test-CAPolicies audits the full CA policy estate: counts enabled/disabled/report-only
    policies, inspects exclusions, scope (All users vs. targeted groups, All cloud apps vs.
    specific apps), device-platform coverage, session controls, and named locations.

    Every finding is returned as a PSCustomObject via New-CheckResult. The function never
    modifies tenant configuration.

.NOTES
    Required Graph Permissions : Policy.Read.All
    License Required            : E3 minimum; risk-condition checks need E5
    Module                      : Microsoft.Graph.Authentication (uses Invoke-MgGraphRequest)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-CAPolicies {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all CA policies
    # -------------------------------------------------------------------------
    try {
        $policiesResponse = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=250' `
            -ErrorAction Stop
        $policies = $policiesResponse.value

        # Page through additional results if present
        $nextLink = $policiesResponse.'@odata.nextLink'
        while ($nextLink) {
            $page      = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $policies += $page.value
            $nextLink  = $page.'@odata.nextLink'
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'CAP-000' `
            -Category 'ConditionalAccess' `
            -Name 'CA Policy Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Policy.Read.All. Error: $_" `
            -Recommendation 'Grant Policy.Read.All to the service principal and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/overview' `
            -CISControl '' `
            -SC300Domain 'Authentication & Access Management' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $enabled    = @($policies | Where-Object { $_.state -eq 'enabled' })
    $disabled   = @($policies | Where-Object { $_.state -eq 'disabled' })
    $reportOnly = @($policies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

    # -------------------------------------------------------------------------
    # CAP-001: Total policy counts and Security Defaults cross-check
    # -------------------------------------------------------------------------
    try {
        $secDefResponse  = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' `
            -ErrorAction Stop
        $secDefaultsOn   = $secDefResponse.isEnabled
    }
    catch {
        $secDefaultsOn = $null   # Insufficient permissions; treat as unknown
    }

    $cap001Status = 'PASS'
    $cap001Detail = "Total CA policies: $($policies.Count) | Enabled: $($enabled.Count) | " +
                    "Report-only: $($reportOnly.Count) | Disabled: $($disabled.Count)"

    if ($enabled.Count -eq 0 -and $reportOnly.Count -gt 0) {
        $cap001Status = 'HIGH'
        $cap001Detail += ' — All CA policies are report-only; no enforcement active.'
    }
    elseif ($enabled.Count -eq 0) {
        # Determine if Security Defaults compensate
        if ($secDefaultsOn -eq $true) {
            $cap001Status = 'INFO'
            $cap001Detail += ' — No CA policies enabled, but Security Defaults is ON (basic MFA enforced).'
        }
        else {
            $cap001Status = 'CRITICAL'
            $cap001Detail += ' — No enabled CA policies AND Security Defaults is disabled. Tenant has no baseline MFA enforcement.'
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'CAP-001' `
        -Category 'ConditionalAccess' `
        -Name 'CA Policy Overview' `
        -Status $cap001Status `
        -Detail $cap001Detail `
        -Recommendation 'Ensure at least one CA policy is enabled and enforcing MFA for all users. Security Defaults is not a substitute for full CA coverage.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/plan-conditional-access' `
        -CISControl 'CIS M365 1.2.1' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # CAP-002: Exclusion hygiene on "All users" policies
    # -------------------------------------------------------------------------
    $allUserPolicies = @($enabled | Where-Object {
        $_.conditions.users.includeUsers -contains 'All'
    })

    $overlyExcluded = @($allUserPolicies | Where-Object {
        $excludedUsers  = @($_.conditions.users.excludeUsers)
        $excludedGroups = @($_.conditions.users.excludeGroups)
        ($excludedUsers.Count + $excludedGroups.Count) -gt 2
    })

    $cap002Status = 'PASS'
    $cap002Detail = "Enabled 'All users' policies: $($allUserPolicies.Count). " +
                    "Policies with more than 2 user/group exclusions: $($overlyExcluded.Count)."
    $cap002Objects = @()

    if ($overlyExcluded.Count -gt 0) {
        $cap002Status  = 'HIGH'
        $cap002Objects = @($overlyExcluded | ForEach-Object {
            "$($_.displayName) (excl. users: $($_.conditions.users.excludeUsers.Count), groups: $($_.conditions.users.excludeGroups.Count))"
        })
        $cap002Detail += " Over-excluded policies: $($cap002Objects -join '; ')"
    }

    $results.Add((New-CheckResult `
        -CheckId 'CAP-002' `
        -Category 'ConditionalAccess' `
        -Name 'CA Policy Exclusion Hygiene' `
        -Status $cap002Status `
        -Detail $cap002Detail `
        -Recommendation 'Minimize exclusions on All-users policies. Use a dedicated break-glass group (max 2 emergency accounts). Review each exclusion for necessity.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/policy-exclusions' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects $cap002Objects))

    # -------------------------------------------------------------------------
    # CAP-003: All users vs. targeted groups (inventory)
    # -------------------------------------------------------------------------
    $targetedGroupPolicies = @($enabled | Where-Object {
        -not ($_.conditions.users.includeUsers -contains 'All') -and
        $_.conditions.users.includeGroups.Count -gt 0
    })

    $results.Add((New-CheckResult `
        -CheckId 'CAP-003' `
        -Category 'ConditionalAccess' `
        -Name 'CA Policy User Scope Inventory' `
        -Status 'INFO' `
        -Detail ("Enabled policies targeting 'All users': $($allUserPolicies.Count). " +
                 "Enabled policies targeting specific groups: $($targetedGroupPolicies.Count). " +
                 "All-user policy names: $(@($allUserPolicies.displayName) -join ', ').") `
        -Recommendation 'Prefer All-users scope with specific exclusions over group-targeted policies to avoid coverage gaps.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-users-groups' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # CAP-004: All cloud apps vs. specific app scope
    # -------------------------------------------------------------------------
    $allAppPolicies = @($enabled | Where-Object {
        $_.conditions.applications.includeApplications -contains 'All'
    })

    $mfaAllAppPolicies = @($allAppPolicies | Where-Object {
        $_.grantControls.builtInControls -contains 'mfa' -or
        $_.grantControls.authenticationStrength -ne $null
    })

    $cap004Status = if ($mfaAllAppPolicies.Count -gt 0) { 'PASS' }
                   elseif ($allAppPolicies.Count -gt 0) { 'MEDIUM' }
                   else { 'MEDIUM' }

    $cap004Detail = "Enabled policies scoped to 'All cloud apps': $($allAppPolicies.Count). " +
                    "Of those requiring MFA: $($mfaAllAppPolicies.Count)."
    if ($mfaAllAppPolicies.Count -eq 0) {
        $cap004Detail += ' No policy enforces MFA across all cloud apps.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'CAP-004' `
        -Category 'ConditionalAccess' `
        -Name 'CA Policy App Scope Coverage' `
        -Status $cap004Status `
        -Detail $cap004Detail `
        -Recommendation 'At minimum one policy should target All cloud apps with MFA requirement for All users to ensure no app is left unprotected.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-cloud-apps' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # CAP-005: Device platform coverage in MFA policies
    # -------------------------------------------------------------------------
    $mfaPolicies = @($enabled | Where-Object {
        $_.grantControls.builtInControls -contains 'mfa' -or
        $_.grantControls.authenticationStrength -ne $null
    })

    # Collect all platforms referenced in MFA policies
    $coveredPlatforms = @($mfaPolicies | ForEach-Object {
        $_.conditions.platforms.includePlatforms
    } | Where-Object { $_ } | Sort-Object -Unique)

    # A policy with no platform condition covers all platforms implicitly
    $unconstrained = @($mfaPolicies | Where-Object {
        -not $_.conditions.platforms -or
        $_.conditions.platforms.includePlatforms.Count -eq 0
    })

    $mobilesCovered = $unconstrained.Count -gt 0 -or
                      ($coveredPlatforms -contains 'iOS' -and $coveredPlatforms -contains 'android')

    $cap005Status = if ($mobilesCovered) { 'PASS' } else { 'MEDIUM' }
    $cap005Detail = "Enabled MFA policies: $($mfaPolicies.Count). " +
                    "Policies with no platform restriction (covers all): $($unconstrained.Count). " +
                    "Explicitly covered platforms: $($coveredPlatforms -join ', ')."
    if (-not $mobilesCovered) {
        $cap005Detail += ' iOS and/or Android not covered by any MFA policy.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'CAP-005' `
        -Category 'ConditionalAccess' `
        -Name 'CA Policy Platform Coverage' `
        -Status $cap005Status `
        -Detail $cap005Detail `
        -Recommendation 'Ensure MFA policies apply to all platforms (Windows, macOS, iOS, Android). Prefer policies with no platform filter rather than explicit per-platform policies.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-conditions#device-platforms' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # CAP-006: Session controls (sign-in frequency, app-enforced restrictions)
    # -------------------------------------------------------------------------
    $sessionPolicies = @($enabled | Where-Object {
        $_.sessionControls -and (
            $_.sessionControls.signInFrequency -or
            $_.sessionControls.applicationEnforcedRestrictions -or
            $_.sessionControls.cloudAppSecurity -or
            $_.sessionControls.persistentBrowser
        )
    })

    $signInFreqPolicies = @($enabled | Where-Object {
        $_.sessionControls.signInFrequency.isEnabled -eq $true
    })

    $cap006Status = if ($signInFreqPolicies.Count -gt 0) { 'PASS' }
                   elseif ($sessionPolicies.Count -gt 0) { 'LOW' }
                   else { 'LOW' }

    $cap006Detail = "Policies with any session control: $($sessionPolicies.Count). " +
                    "Policies with sign-in frequency control: $($signInFreqPolicies.Count)."
    if ($signInFreqPolicies.Count -eq 0) {
        $cap006Detail += ' No sign-in frequency controls found — sessions may persist indefinitely on sensitive apps.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'CAP-006' `
        -Category 'ConditionalAccess' `
        -Name 'CA Session Controls' `
        -Status $cap006Status `
        -Detail $cap006Detail `
        -Recommendation 'Configure sign-in frequency (e.g. 1 hour for admins, 8 hours for users) on sensitive apps. Enable app-enforced restrictions for SharePoint/Exchange on unmanaged devices.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/howto-conditional-access-session-lifetime' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # CAP-007: Named locations defined
    # -------------------------------------------------------------------------
    try {
        $namedLocResponse  = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?$top=100' `
            -ErrorAction Stop
        $namedLocations    = $namedLocResponse.value
        $ipLocations       = @($namedLocations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' })
        $countryLocations  = @($namedLocations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.countryNamedLocation' })

        $cap007Status = if ($namedLocations.Count -gt 0) { 'PASS' } else { 'LOW' }
        $cap007Detail = "Named locations: $($namedLocations.Count) total " +
                        "(IP-based: $($ipLocations.Count), country-based: $($countryLocations.Count))."
        if ($namedLocations.Count -eq 0) {
            $cap007Detail += ' No named locations defined — location-based risk conditions cannot be leveraged.'
        }
    }
    catch {
        $cap007Status = 'INFO'
        $cap007Detail = "Named locations check skipped: insufficient permissions or API error. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'CAP-007' `
        -Category 'ConditionalAccess' `
        -Name 'Named Locations Configured' `
        -Status $cap007Status `
        -Detail $cap007Detail `
        -Recommendation 'Define trusted IP ranges and corporate countries as named locations. Use them in CA policies to reduce false positives and enable location-based risk rules.' `
        -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/location-condition' `
        -CISControl '' `
        -SC300Domain 'Authentication & Access Management' `
        -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # Optional: Full policy details when -Detailed is requested
    # -------------------------------------------------------------------------
    if ($Detailed) {
        foreach ($policy in $enabled) {
            $results.Add((New-CheckResult `
                -CheckId 'CAP-DET' `
                -Category 'ConditionalAccess' `
                -Name "Policy Detail: $($policy.displayName)" `
                -Status 'INFO' `
                -Detail ("State: $($policy.state) | " +
                         "IncludeUsers: $($policy.conditions.users.includeUsers -join ',') | " +
                         "IncludeApps: $($policy.conditions.applications.includeApplications -join ',') | " +
                         "GrantControls: $($policy.grantControls.builtInControls -join ',') | " +
                         "Platforms: $($policy.conditions.platforms.includePlatforms -join ',') | " +
                         "ClientAppTypes: $($policy.conditions.clientAppTypes -join ',') | " +
                         "ExcludeUsers: $($policy.conditions.users.excludeUsers.Count) | " +
                         "ExcludeGroups: $($policy.conditions.users.excludeGroups.Count)") `
                -Recommendation '' `
                -Reference 'https://learn.microsoft.com/entra/identity/conditional-access/overview' `
                -CISControl '' `
                -SC300Domain 'Authentication & Access Management' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }

    return $results
}
