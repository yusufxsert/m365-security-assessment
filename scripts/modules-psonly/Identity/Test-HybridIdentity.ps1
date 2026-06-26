#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Checks Entra ID hybrid identity configuration and sync health. PS-only variant.

.DESCRIPTION
    Evaluates Entra Connect sync status, sync lag, provisioning errors,
    authentication method inference (via domain federation status), seamless SSO,
    and whether the sync service account holds elevated privileges.
    Checks: HYB-001 through HYB-005.

    WHY PS-ONLY:
        This variant replaces all Invoke-MgGraphRequest calls with typed SDK cmdlets so that
        the script runs with only an interactive Connect-MgGraph session — no app registration
        or client secret is required. Suitable for ad-hoc assessments by an administrator.

    SEE ALSO:
        Graph variant: scripts/modules/Identity/Test-HybridIdentity.ps1

    CHANGES vs. Graph variant:
        HYB-001: Get-MgOrganization already used in original — unchanged.
        HYB-002: Invoke-MgGraphRequest GET /domains -> Get-MgDomain -All
                 Property filtering: -Property 'id,authenticationType,isDefault' retained.
        HYB-003: Invoke-MgGraphRequest GET /servicePrincipals filter by displayName
                 -> Get-MgServicePrincipal -Filter "displayName eq 'Seamless Single Sign-On'"
                 NOTE: Seamless SSO / PTA detailed health status is NOT available via any
                 PS SDK cmdlet — detailed health data lives in Azure AD Connect Health portal.
                 This check detects only the presence of the 'Seamless Single Sign-On' SP,
                 identical to the Graph variant. For PTA agent health and SSSO configuration
                 detail, see: https://entra.microsoft.com/#view/Microsoft_AAD_Connect_Provisioning
        HYB-004: Get-MgOrganization already used — provisioningErrors read from returned object.
        HYB-005: Get-MgDirectoryRole -All and Get-MgDirectoryRoleMember already used — unchanged.

    STUB NOTE (HYB-003):
        PTA agent health, SSSO session key age, and ADFS relying party details are not
        accessible via Microsoft Graph or the PS SDK. For those details, use:
            - Entra Connect Health portal: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/HealthMenuBlade
            - Get-AzureADPasswordProtectionDCAgent (legacy MSOL module, on-premises only)

.NOTES
    Required connection  : Connect-MgGraph -Scopes "Organization.Read.All","Directory.Read.All"
    Required scopes      : Organization.Read.All, Directory.Read.All, RoleManagement.Read.Directory
    Required modules     : Microsoft.Graph.Authentication
                           Microsoft.Graph.Identity.DirectoryManagement

    License: E3 minimum.
    Assumes New-AssessmentResult is dot-sourced from scripts/helpers before calling this function.
#>

function Test-HybridIdentity {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Fetch org once for multiple checks
    $org = $null
    try {
        $org = Get-MgOrganization -Property 'id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesProvisioningErrors' -ErrorAction Stop
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-000: Organization Data' `
            -Status    'Info' `
            -Detail    "Could not retrieve organization data. All hybrid checks skipped. Required: Organization.Read.All. Error: $_" `
            -Recommendation 'Grant Organization.Read.All and reconnect: Connect-MgGraph -Scopes "Organization.Read.All","Directory.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-health-agent-install' `
            -Category  'Identity' `
            -Severity  'Info'))
        return $results
    }

    $syncEnabled = $org.OnPremisesSyncEnabled
    $isHybrid = $syncEnabled -eq $true

    # HYB-001: Entra Connect sync status and lag
    try {
        if (-not $isHybrid) {
            $results.Add((New-AssessmentResult `
                -CheckName 'HYB-001: Entra Connect Sync Status' `
                -Status    'Info' `
                -Detail    "OnPremisesSyncEnabled: false/null. Cloud-only tenant detected. Hybrid identity checks HYB-001 through HYB-005 are not applicable." `
                -Recommendation 'No action required for cloud-only tenants.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-azure-ad-connect' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl ''))
            return $results
        }

        $lastSync = $org.OnPremisesLastSyncDateTime
        $syncAgeMinutes = if ($lastSync) {
            [math]::Round(((Get-Date) - $lastSync.ToLocalTime()).TotalMinutes, 0)
        } else { $null }
        $syncAgeHours = if ($syncAgeMinutes) { [math]::Round($syncAgeMinutes / 60, 1) } else { $null }

        if ($null -eq $lastSync) {
            $results.Add((New-AssessmentResult `
                -CheckName 'HYB-001: Entra Connect Sync Status' `
                -Status    'Fail' `
                -Detail    "OnPremisesSyncEnabled is true but OnPremisesLastSyncDateTime is null. Sync may never have completed or data is not visible via API." `
                -Recommendation 'Verify Entra Connect is running and has completed at least one sync cycle. Check Entra Connect Health for alerts.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-health-sync' `
                -Category  'Identity' `
                -Severity  'High' `
                -CisControl ''))
        }
        elseif ($syncAgeMinutes -gt 180) {
            $results.Add((New-AssessmentResult `
                -CheckName 'HYB-001: Entra Connect Sync Status' `
                -Status    'Fail' `
                -Detail    "Last successful sync: $lastSync ($syncAgeHours hours ago). Sync is stale (threshold: 3 hours). Identity changes from on-premises may not have propagated." `
                -Recommendation 'Investigate Entra Connect sync errors. Check the Entra Connect Health dashboard and the Application Event Log on the sync server.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-health-sync' `
                -Category  'Identity' `
                -Severity  'High' `
                -MitreId   'T1485' `
                -MitreTactic 'Impact' `
                -CisControl ''))
        }
        else {
            $results.Add((New-AssessmentResult `
                -CheckName 'HYB-001: Entra Connect Sync Status' `
                -Status    'Pass' `
                -Detail    "Entra Connect sync is active. Last sync: $lastSync ($syncAgeMinutes minutes ago)." `
                -Recommendation 'Monitor sync health via Entra Connect Health. Set up alerts for sync failures.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-health-sync' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl ''))
        }
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-001: Entra Connect Sync Status' `
            -Status    'Info' `
            -Detail    "Check failed: $_" `
            -Recommendation 'Verify Organization.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-health-sync' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # HYB-002: Sync method inference (PHS / PTA / Federation) via domain authentication type
    try {
        $domains = Get-MgDomain -All -Property 'id,authenticationType,isDefault' -ErrorAction Stop

        $federatedDomains = @($domains | Where-Object { $_.AuthenticationType -eq 'Federated' })
        $managedDomains   = @($domains | Where-Object { $_.AuthenticationType -eq 'Managed' })

        $syncMethod = if ($federatedDomains.Count -gt 0) {
            "Federation (ADFS/PingFederate detected — $($federatedDomains.Count) federated domain(s))"
        } else {
            "Managed (Password Hash Sync or Pass-through Auth — $($managedDomains.Count) managed domain(s))"
        }

        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-002: Authentication Method (PHS/PTA/Federation)' `
            -Status    'Info' `
            -Detail    "Detected sync method: $syncMethod. Federated domains rely on on-premises ADFS. Managed domains use PHS or PTA directly in Entra ID." `
            -Recommendation 'Password Hash Sync is recommended over PTA or Federation for cloud resilience and leaked credential detection. Consider migrating from Federation if on-premises SSO is not strictly required.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-phs' `
            -Category  'Identity' `
            -Severity  'Info' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-002: Authentication Method' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Directory.Read.All. Error: $_" `
            -Recommendation 'Grant Directory.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-phs' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # HYB-003: Seamless SSO presence (inferred via service principal display name)
    # NOTE: PTA agent health and SSSO configuration detail are NOT available via Graph or PS SDK.
    # For those, use Entra Connect Health portal:
    # https://entra.microsoft.com/#view/Microsoft_AAD_IAM/HealthMenuBlade
    try {
        $ssoSps = Get-MgServicePrincipal -Filter "displayName eq 'Seamless Single Sign-On'" `
            -Property 'id,displayName,appId' -ErrorAction Stop
        $ssoEnabled = @($ssoSps).Count -gt 0

        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-003: Seamless SSO Status' `
            -Status    'Info' `
            -Detail    "Seamless SSO service principal found: $ssoEnabled. Seamless SSO enables transparent Kerberos-based authentication for domain-joined devices. NOTE: Detailed PTA/SSSO health data (agent status, session key age) is only available in the Entra Connect Health portal — https://entra.microsoft.com/#view/Microsoft_AAD_IAM/HealthMenuBlade" `
            -Recommendation 'Seamless SSO is acceptable when required for legacy apps. For modern workloads, prefer WHFB (Windows Hello for Business) or FIDO2. Ensure the AZUREADSSOACC computer account in AD is protected.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso' `
            -Category  'Identity' `
            -Severity  'Info' `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-003: Seamless SSO Status' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions or API error. Required: Directory.Read.All. Error: $_" `
            -Recommendation 'Grant Directory.Read.All and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # HYB-004: Provisioning errors (from organization object retrieved above)
    try {
        $provErrors = $org.OnPremisesProvisioningErrors
        $errorCount = if ($provErrors) { @($provErrors).Count } else { 0 }

        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-004: Directory Provisioning Errors' `
            -Status    (if ($errorCount -eq 0) { 'Pass' } else { 'Fail' }) `
            -Detail    "On-premises provisioning errors: $errorCount. Provisioning errors indicate objects that failed to sync from AD to Entra ID." `
            -Recommendation 'Resolve all provisioning errors in Entra Connect. Common causes: duplicate UPNs, invalid characters, attribute conflicts. Use the Troubleshoot Sync Errors tool in Entra admin center.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-sync-errors' `
            -Category  'Identity' `
            -Severity  (if ($errorCount -gt 0) { 'High' } else { 'Info' }) `
            -CisControl ''))
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-004: Provisioning Errors' `
            -Status    'Info' `
            -Detail    "Check skipped: error reading provisioning errors. Error: $_" `
            -Recommendation 'Verify Organization.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/tshoot-connect-sync-errors' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # HYB-005: Sync service account with elevated privileges
    try {
        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $privilegedRoleNames = @(
            'Global Administrator', 'Privileged Role Administrator', 'Directory Synchronization Accounts',
            'Hybrid Identity Administrator'
        )
        $privilegedRoles = $allRoles | Where-Object { $_.DisplayName -in $privilegedRoleNames }

        $syncAccountsInPrivRoles = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($role in $privilegedRoles) {
            if ($role.DisplayName -eq 'Directory Synchronization Accounts') { continue }
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
                foreach ($member in $members) {
                    $onPremSync = $member.AdditionalProperties['onPremisesSyncEnabled']
                    $upn = $member.AdditionalProperties['userPrincipalName']
                    $looksLikeSyncAccount = $upn -match '(?i)(^MSOL_|^Sync_|MSOL|AADConnect|ADSync)'
                    if ($onPremSync -eq $true -or $looksLikeSyncAccount) {
                        $syncAccountsInPrivRoles.Add([PSCustomObject]@{
                            UPN      = $upn
                            RoleName = $role.DisplayName
                            IsSynced = $onPremSync
                        })
                    }
                }
            }
            catch { Write-Verbose "Could not enumerate $($role.DisplayName): $_" }
        }

        if ($syncAccountsInPrivRoles.Count -gt 0) {
            $detail = ($syncAccountsInPrivRoles | ForEach-Object { "$($_.UPN) [$($_.RoleName)]" }) -join '; '
            $results.Add((New-AssessmentResult `
                -CheckName 'HYB-005: Sync Service Account Privileges' `
                -Status    'Fail' `
                -Detail    "$($syncAccountsInPrivRoles.Count) synced/sync-pattern account(s) found in privileged roles: $detail" `
                -Recommendation 'Remove on-premises synced accounts from Global Administrator and other privileged roles. Entra Connect service accounts need only the Directory Synchronization Accounts role.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions' `
                -Category  'Identity' `
                -Severity  'High' `
                -MitreId   'T1078.002' `
                -MitreTactic 'PrivilegeEscalation' `
                -CisControl 'CIS M365 1.1.4'))
        }
        else {
            $results.Add((New-AssessmentResult `
                -CheckName 'HYB-005: Sync Service Account Privileges' `
                -Status    'Pass' `
                -Detail    "No on-premises synced accounts detected in elevated Entra ID roles (Global Admin, Privileged Role Admin, Hybrid Identity Admin)." `
                -Recommendation 'Continue to audit periodically. Verify Entra Connect service account has only Directory Synchronization Accounts role.' `
                -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions' `
                -Category  'Identity' `
                -Severity  'Info' `
                -CisControl 'CIS M365 1.1.4'))
        }
    }
    catch {
        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-005: Sync Service Account Privileges' `
            -Status    'Info' `
            -Detail    "Check skipped: insufficient permissions. Required: RoleManagement.Read.Directory. Error: $_" `
            -Recommendation 'Grant RoleManagement.Read.Directory and reconnect.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    return $results
}
