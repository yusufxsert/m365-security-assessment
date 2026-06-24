#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Checks Entra ID hybrid identity configuration and sync health.
.DESCRIPTION
    Evaluates Entra Connect sync status, sync lag, provisioning errors,
    seamless SSO presence, and whether the sync service account holds
    elevated privileges.
    Checks: HYB-001 through HYB-005.
.NOTES
    Required Permissions:
        Organization.Read.All
        Directory.Read.All
        RoleManagement.Read.Directory
    License: E3 minimum
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
            -Recommendation 'Grant Organization.Read.All to the service principal.' `
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
            # Return early — all remaining checks require hybrid
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
            # > 3 hours — sync is stale
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

    # HYB-002: Sync method (PHS / PTA / Federation)
    try {
        # The Graph API does not directly expose the sync method type.
        # We infer from onPremisesProvisioningErrors and domain federation status.
        $domains = Invoke-MgGraphRequest -Method GET `
            -Uri 'https://graph.microsoft.com/v1.0/domains?$select=id,authenticationType,isDefault' `
            -ErrorAction Stop

        $federatedDomains = $domains.value | Where-Object { $_.authenticationType -eq 'Federated' }
        $managedDomains   = $domains.value | Where-Object { $_.authenticationType -eq 'Managed' }

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
            -Recommendation 'Grant Directory.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/whatis-phs' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # HYB-003: Seamless SSO
    try {
        # Seamless SSO leaves a service principal named 'Seamless Single Sign-On' in the tenant
        $ssoSp = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq 'Seamless Single Sign-On'&`$select=id,displayName,appId" `
            -ErrorAction Stop

        $ssoEnabled = $ssoSp.value.Count -gt 0

        $results.Add((New-AssessmentResult `
            -CheckName 'HYB-003: Seamless SSO Status' `
            -Status    'Info' `
            -Detail    "Seamless SSO service principal found: $ssoEnabled. Seamless SSO enables transparent Kerberos-based authentication for domain-joined devices." `
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
            -Recommendation 'Grant Directory.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-sso' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    # HYB-004: Provisioning errors
    try {
        $provErrors = $org.OnPremisesProvisioningErrors
        $errorCount = if ($provErrors) { $provErrors.Count } else { 0 }

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
        # Entra Connect creates accounts with patterns like MSOL_*, Sync_*, or similar.
        # Find users synced from on-premises (onPremisesSyncEnabled=true) who hold privileged roles.
        $allRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        $privilegedRoleNames = @(
            'Global Administrator', 'Privileged Role Administrator', 'Directory Synchronization Accounts',
            'Hybrid Identity Administrator'
        )
        $privilegedRoles = $allRoles | Where-Object { $_.DisplayName -in $privilegedRoleNames }

        $syncAccountsInPrivRoles = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($role in $privilegedRoles) {
            # Skip "Directory Synchronization Accounts" — that role is expected for the sync account
            if ($role.DisplayName -eq 'Directory Synchronization Accounts') { continue }
            try {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction Stop
                foreach ($member in $members) {
                    $onPremSync = $member.AdditionalProperties['onPremisesSyncEnabled']
                    $upn = $member.AdditionalProperties['userPrincipalName']
                    # Also catch MSOL_ pattern accounts which are created by AAD Connect
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
            -Recommendation 'Grant RoleManagement.Read.Directory to the service principal.' `
            -Reference 'https://learn.microsoft.com/entra/identity/hybrid/connect/reference-connect-accounts-permissions' `
            -Category  'Identity' `
            -Severity  'Info'))
    }

    return $results
}
