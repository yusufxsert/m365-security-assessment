#Requires -Version 7.0

<#
.SYNOPSIS
    Audits app registrations for credential hygiene, dangerous permissions, and lifecycle gaps.
    PS-only variant.

.DESCRIPTION
    Test-AppRegistrations evaluates the tenant's application registrations for security risks:
    expired or soon-expiring credentials, long-lived secrets, multi-tenant apps, privileged API
    permissions, missing owners, and potentially abandoned registrations.

    All findings are returned as PSCustomObject via New-CheckResult. No tenant state is modified.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/WorkloadIdentities/Test-AppRegistrations.ps1

    CHANGES vs. Graph variant:
        APP-000/main fetch: Invoke-MgGraphRequest paged GET /applications
                            -> Get-MgApplication -All
                            -Property parameter carries over all required fields.
        APP-005 (owners):   Invoke-MgGraphRequest GET /applications/{id}/owners
                            -> Get-MgApplicationOwner -ApplicationId {id} -All
        APP-006 (SPs):      Invoke-MgGraphRequest paged GET /servicePrincipals?$select=appId
                            -> Get-MgServicePrincipal -All -Property 'appId'

.NOTES
    Required connection  : Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All"
    Required scopes      : Application.Read.All, Directory.Read.All
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Applications

    License Required            : E3 minimum
    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.

    Checks implemented:
        APP-001  Expiring / expired credentials (secrets + certificates)
        APP-002  Long-lived credentials (> 1 year validity)
        APP-003  Multi-tenant app registrations
        APP-004  App registrations with privileged API permissions
        APP-005  App registrations with no owners (admin-consented)
        APP-006  Abandoned app registrations (no service principal)
#>

function Test-AppRegistrations {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Retrieve all app registrations via Get-MgApplication -All
    # -------------------------------------------------------------------------
    $apps = $null
    try {
        $apps = Get-MgApplication -All `
            -Property 'id,appId,displayName,signInAudience,passwordCredentials,keyCredentials,requiredResourceAccess' `
            -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'APP-000' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration Retrieval' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or API error. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and reconnect: Connect-MgGraph -Scopes "Application.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
        return $results
    }

    $now    = Get-Date
    $days30 = $now.AddDays(30)
    $days90 = $now.AddDays(90)

    # -------------------------------------------------------------------------
    # APP-001: Expired or expiring credentials
    # -------------------------------------------------------------------------
    $expiredObjects   = [System.Collections.Generic.List[string]]::new()
    $critical30Days   = [System.Collections.Generic.List[string]]::new()
    $medium90Days     = [System.Collections.Generic.List[string]]::new()

    foreach ($app in $apps) {
        $allCreds = @()
        if ($app.PasswordCredentials) { $allCreds += $app.PasswordCredentials }
        if ($app.KeyCredentials)      { $allCreds += $app.KeyCredentials }

        foreach ($cred in $allCreds) {
            if (-not $cred.EndDateTime) { continue }
            $expiry = [datetime]$cred.EndDateTime
            $label  = "$($app.DisplayName) [expires: $($expiry.ToString('yyyy-MM-dd'))]"
            if ($expiry -lt $now) {
                $expiredObjects.Add($label)
            }
            elseif ($expiry -lt $days30) {
                $critical30Days.Add($label)
            }
            elseif ($expiry -lt $days90) {
                $medium90Days.Add($label)
            }
        }
    }

    if ($expiredObjects.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-001' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Expired Credentials' `
            -Status 'CRITICAL' `
            -Detail "Found $($expiredObjects.Count) app(s) with expired credentials. These apps may be broken and could block service access or indicate stale attack surface." `
            -Recommendation 'Remove or rotate expired secrets and certificates immediately. Automate renewal using managed identities or federated credentials where possible.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/credential-certificate-pdp' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $expiredObjects.ToArray()))
    }

    if ($critical30Days.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-001' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Credentials Expiring Within 30 Days' `
            -Status 'HIGH' `
            -Detail "Found $($critical30Days.Count) app(s) with credentials expiring within 30 days." `
            -Recommendation 'Rotate these credentials before expiry. Prefer certificate-based or federated credentials over client secrets. Implement lifecycle alerts via Azure Monitor.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/credential-certificate-pdp' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $critical30Days.ToArray()))
    }

    if ($medium90Days.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-001' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Credentials Expiring Within 90 Days' `
            -Status 'MEDIUM' `
            -Detail "Found $($medium90Days.Count) app(s) with credentials expiring within 90 days." `
            -Recommendation 'Plan credential rotation. Consider moving to managed identities or workload identity federation to eliminate secret management.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/credential-certificate-pdp' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $medium90Days.ToArray()))
    }

    if ($expiredObjects.Count -eq 0 -and $critical30Days.Count -eq 0 -and $medium90Days.Count -eq 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-001' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Credential Expiry' `
            -Status 'PASS' `
            -Detail "No expired or near-expiring credentials found across $($apps.Count) app registrations." `
            -Recommendation 'Continue monitoring credential expiry. Automate renewal alerts.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/credential-certificate-pdp' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # APP-002: Long-lived credentials (> 1 year validity)
    # -------------------------------------------------------------------------
    $veryLongLived = [System.Collections.Generic.List[string]]::new()
    $longLived     = [System.Collections.Generic.List[string]]::new()

    foreach ($app in $apps) {
        foreach ($cred in $app.PasswordCredentials) {
            if (-not $cred.StartDateTime -or -not $cred.EndDateTime) { continue }
            $start    = [datetime]$cred.StartDateTime
            $end      = [datetime]$cred.EndDateTime
            $spanDays = ($end - $start).TotalDays
            $label    = "$($app.DisplayName) [valid: $($start.ToString('yyyy-MM-dd')) - $($end.ToString('yyyy-MM-dd')), $([math]::Round($spanDays/365,1)) years]"

            if ($spanDays -gt 730) {
                $veryLongLived.Add($label)
            }
            elseif ($spanDays -gt 365) {
                $longLived.Add($label)
            }
        }
    }

    if ($veryLongLived.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-002' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Secrets Valid > 2 Years' `
            -Status 'HIGH' `
            -Detail "Found $($veryLongLived.Count) client secret(s) with validity period exceeding 2 years. Long-lived secrets increase the blast radius of credential theft." `
            -Recommendation 'Rotate these secrets immediately with a maximum 1-year validity. Prefer federated identity credentials (no secrets) or managed identities.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/workload-identity-federation' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $veryLongLived.ToArray()))
    }

    if ($longLived.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-002' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Secrets Valid > 1 Year' `
            -Status 'MEDIUM' `
            -Detail "Found $($longLived.Count) client secret(s) with validity period between 1 and 2 years." `
            -Recommendation 'Rotate annually at minimum. Evaluate migration to federated credentials or managed identities to remove secret management overhead entirely.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/workload-identity-federation' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $longLived.ToArray()))
    }

    if ($veryLongLived.Count -eq 0 -and $longLived.Count -eq 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-002' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Credential Lifetime' `
            -Status 'PASS' `
            -Detail 'No client secrets with validity period exceeding 1 year found.' `
            -Recommendation 'Maintain short-lived secrets. Prefer managed identities or federated credentials for new integrations.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/workload-identity-federation' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # APP-003: Multi-tenant app registrations
    # -------------------------------------------------------------------------
    $multiTenantAudiences = @('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount')
    $multiTenantApps = @($apps | Where-Object { $_.SignInAudience -in $multiTenantAudiences })

    if ($multiTenantApps.Count -gt 0) {
        $dangerousRoles = @(
            '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9',
            '19dbc75e-c2e2-444c-a770-ec69d8559fc7',
            'e2a3a72e-5f79-4c64-b1b1-878b674786c9',
            'b633e1c5-b582-4048-a93e-9f11b44c7e96',
            '810c84a8-4a9e-49e6-bf7d-12d183f40d01',
            '7ab1d382-f21e-4acd-a863-ba3e13f7da61'
        )

        $broadPermApps = [System.Collections.Generic.List[string]]::new()
        foreach ($app in $multiTenantApps) {
            $hasDangerous = $false
            foreach ($rra in $app.RequiredResourceAccess) {
                foreach ($ra in $rra.ResourceAccess) {
                    if ($ra.Type -eq 'Role' -and $ra.Id -in $dangerousRoles) {
                        $hasDangerous = $true
                        break
                    }
                }
                if ($hasDangerous) { break }
            }
            if ($hasDangerous) {
                $broadPermApps.Add("$($app.DisplayName) [audience: $($app.SignInAudience)]")
            }
        }

        $multiStatus = if ($broadPermApps.Count -gt 0) { 'HIGH' } else { 'MEDIUM' }
        $multiDetail = "Found $($multiTenantApps.Count) multi-tenant app registration(s) (signInAudience: AzureADMultipleOrgs or AzureADandPersonalMicrosoftAccount)."
        if ($broadPermApps.Count -gt 0) {
            $multiDetail += " Of these, $($broadPermApps.Count) have broad/privileged API permissions — high risk for cross-tenant abuse."
        }
        $affectedMulti = if ($broadPermApps.Count -gt 0) {
            $broadPermApps.ToArray()
        } else {
            @($multiTenantApps | ForEach-Object { "$($_.DisplayName) [audience: $($_.SignInAudience)]" })
        }

        $results.Add((New-CheckResult `
            -CheckId 'APP-003' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Multi-Tenant Applications' `
            -Status $multiStatus `
            -Detail $multiDetail `
            -Recommendation 'Restrict app registrations to single-tenant (AzureADMyOrg) unless multi-tenant access is explicitly required. For multi-tenant apps, minimise API permissions and enforce publisher verification.' `
            -Reference 'https://learn.microsoft.com/entra/identity-platform/single-and-multi-tenant-apps' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $affectedMulti))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'APP-003' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Multi-Tenant Applications' `
            -Status 'PASS' `
            -Detail 'No multi-tenant app registrations found.' `
            -Recommendation 'Continue restricting new app registrations to single-tenant audience.' `
            -Reference 'https://learn.microsoft.com/entra/identity-platform/single-and-multi-tenant-apps' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # APP-004: Apps with privileged API permissions (application type)
    # -------------------------------------------------------------------------
    $privilegedRoleMap = @{
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = 'Application.ReadWrite.All'
        '19dbc75e-c2e2-444c-a770-ec69d8559fc7' = 'Directory.ReadWrite.All'
        'e2a3a72e-5f79-4c64-b1b1-878b674786c9' = 'Mail.ReadWrite (application)'
        'b633e1c5-b582-4048-a93e-9f11b44c7e96' = 'Mail.Send (application)'
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = 'RoleManagement.ReadWrite.Directory'
        '741f803b-c850-494e-b5df-cde7c675a1ca' = 'User.ReadWrite.All (application)'
        '5b567255-7703-4780-807c-7be8301ae99b' = 'Group.ReadWrite.All (application)'
    }

    $privilegedApps = [System.Collections.Generic.List[string]]::new()

    foreach ($app in $apps) {
        $matchedPerms = [System.Collections.Generic.List[string]]::new()
        foreach ($rra in $app.RequiredResourceAccess) {
            foreach ($ra in $rra.ResourceAccess) {
                if ($ra.Type -eq 'Role' -and $privilegedRoleMap.ContainsKey($ra.Id)) {
                    $matchedPerms.Add($privilegedRoleMap[$ra.Id])
                }
            }
        }
        if ($matchedPerms.Count -gt 0) {
            $privilegedApps.Add("$($app.DisplayName) [perms: $($matchedPerms -join ', ')]")
        }
    }

    if ($privilegedApps.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-004' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Privileged API Permissions (Application Type)' `
            -Status 'HIGH' `
            -Detail "Found $($privilegedApps.Count) app registration(s) requesting highly privileged application-type permissions (e.g. Directory.ReadWrite.All, Mail.ReadWrite). Application permissions grant access without user context and require admin consent." `
            -Recommendation 'Review each app — confirm the permission is actually required. Replace application permissions with delegated permissions where possible. Enforce Conditional Access for workload identities.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $privilegedApps.ToArray()))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'APP-004' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Privileged API Permissions' `
            -Status 'PASS' `
            -Detail 'No app registrations with highly privileged application-type permissions found.' `
            -Recommendation 'Continue auditing permissions when onboarding new applications.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/grant-admin-consent' `
            -CISControl 'CIS M365 1.6' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # APP-005: App registrations with no owners (that have permissions)
    # Uses Get-MgApplicationOwner -ApplicationId {id} -All
    # -------------------------------------------------------------------------
    $appsWithPerms = @($apps | Where-Object { $_.RequiredResourceAccess.Count -gt 0 })
    $noOwnerApps   = [System.Collections.Generic.List[string]]::new()

    foreach ($app in $appsWithPerms) {
        try {
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction Stop
            if (@($owners).Count -eq 0) {
                $noOwnerApps.Add($app.DisplayName)
            }
        }
        catch {
            Write-Verbose "APP-005: Could not retrieve owners for $($app.DisplayName): $_"
        }
    }

    if ($noOwnerApps.Count -gt 0) {
        $results.Add((New-CheckResult `
            -CheckId 'APP-005' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Applications Without Owners' `
            -Status 'MEDIUM' `
            -Detail "Found $($noOwnerApps.Count) app registration(s) with API permissions but no assigned owner. Ownerless apps have no accountable party for credential rotation or permission review." `
            -Recommendation 'Assign at least one non-privileged owner to every application with permissions. The owner should be responsible for credential lifecycle and permission reviews.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/assign-app-owners' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects $noOwnerApps.ToArray()))
    }
    else {
        $results.Add((New-CheckResult `
            -CheckId 'APP-005' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Applications Without Owners' `
            -Status 'PASS' `
            -Detail "All $($appsWithPerms.Count) app registrations with permissions have at least one owner." `
            -Recommendation 'Continue assigning owners when registering new applications.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/assign-app-owners' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # APP-006: Abandoned app registrations (no corresponding service principal)
    # Uses Get-MgServicePrincipal -All -Property 'appId'
    # -------------------------------------------------------------------------
    try {
        $allSPs = Get-MgServicePrincipal -All -Property 'appId' -ErrorAction Stop
        $spAppIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($sp in $allSPs) { [void]$spAppIds.Add($sp.AppId) }

        $abandonedApps = @($apps | Where-Object { -not $spAppIds.Contains($_.AppId) })

        if ($abandonedApps.Count -gt 0) {
            $abandonedNames = @($abandonedApps | ForEach-Object { $_.DisplayName })
            $results.Add((New-CheckResult `
                -CheckId 'APP-006' `
                -Category 'WorkloadIdentities' `
                -Name 'App Registration: Potentially Abandoned (No Service Principal)' `
                -Status 'MEDIUM' `
                -Detail "Found $($abandonedApps.Count) app registration(s) with no matching service principal in this tenant. These may be unused or created erroneously. They still occupy credential slots and show up in admin consent flows." `
                -Recommendation 'Review each abandoned registration. Delete those with no business justification. If needed, create a service principal via the admin consent endpoint or Azure Portal.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/delete-application-portal' `
                -CISControl '' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects $abandonedNames))
        }
        else {
            $results.Add((New-CheckResult `
                -CheckId 'APP-006' `
                -Category 'WorkloadIdentities' `
                -Name 'App Registration: Abandoned Applications' `
                -Status 'PASS' `
                -Detail "All $($apps.Count) app registrations have a corresponding service principal." `
                -Recommendation 'Periodically review app registrations for stale or orphaned entries.' `
                -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/delete-application-portal' `
                -CISControl '' `
                -SC300Domain 'Workload Identities' `
                -LicenseRequired 'E3' `
                -AffectedObjects @()))
        }
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'APP-006' `
            -Category 'WorkloadIdentities' `
            -Name 'App Registration: Abandoned Applications' `
            -Status 'INFO' `
            -Detail "Check skipped: could not retrieve service principals. Required: Application.Read.All. Error: $_" `
            -Recommendation 'Grant Application.Read.All and retry.' `
            -Reference 'https://learn.microsoft.com/entra/identity/enterprise-apps/delete-application-portal' `
            -CISControl '' `
            -SC300Domain 'Workload Identities' `
            -LicenseRequired 'E3' `
            -AffectedObjects @()))
    }

    return $results
}
