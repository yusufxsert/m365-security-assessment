#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Microsoft Purview audit log configuration and Insider Risk Management.

.DESCRIPTION
    Test-PurviewAudit checks whether the audit log is accessible and retained,
    whether mailbox audit is enabled at the organization level (via EXO if available),
    whether the audit log query API is functional, and whether Insider Risk Management
    (IRM) policies are configured for E5 tenants.

    All findings are returned as PSCustomObject via New-CheckResult. The function
    is read-only and makes no changes to tenant configuration.

.NOTES
    Required Graph Permissions:
        AuditLog.Read.All

    Exchange Online (optional, for PAD-002):
        Exchange.ManageAsApp or EXO module connected

    License Required:
        Basic audit: E3
        Extended retention (1 year), advanced audit: E5

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling.
#>

function Test-PurviewAudit {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # PAD-001: Audit log retention configured and accessible
    # -------------------------------------------------------------------------
    try {
        $auditQueryUri = 'https://graph.microsoft.com/v1.0/security/auditLog/queries?$top=1'
        $auditQueryResp = Invoke-MgGraphRequest -Method GET -Uri $auditQueryUri -ErrorAction Stop

        # Also test a basic audit log search to confirm data is flowing
        $testQueryBody = @{
            displayName = 'AssessmentTest'
            filterStartDateTime = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
            filterEndDateTime   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
            recordTypeFilters   = @('azureActiveDirectory')
        }
        try {
            $testQueryResp = Invoke-MgGraphRequest -Method POST `
                -Uri 'https://graph.microsoft.com/v1.0/security/auditLog/queries' `
                -Body ($testQueryBody | ConvertTo-Json -Depth 5) `
                -ContentType 'application/json' `
                -ErrorAction Stop
            $auditAccessible = $true
        }
        catch {
            $auditAccessible = $false
            Write-Verbose "Could not create test audit query: $_"
        }

        # Detect license tier based on organization licenses
        try {
            $subscribedSkusResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus' `
                -ErrorAction Stop
            $skus = $subscribedSkusResp.value
            $hasE5 = $skus | Where-Object { $_.skuPartNumber -match 'ENTERPRISEPREMIUM|M365EDU_A5|SPE_E5|COMPLIANCE' -and $_.capabilityStatus -eq 'Enabled' }
            $retentionNote = if ($hasE5) { 'E5 license detected — audit logs retained up to 1 year (premium events 10 years with Audit Premium add-on).' }
                             else { 'E3 license — default audit retention is 90 days.' }
        }
        catch {
            $retentionNote = 'License check unavailable. Default audit retention may be 90 days (E3) or 1 year (E5).'
            $hasE5 = $null
        }

        if (-not $auditAccessible) {
            $pad001Status = 'HIGH'
            $pad001Detail = "Audit log API accessible but test query failed — audit logging may be partially disabled. $retentionNote"
        }
        else {
            $pad001Status = 'PASS'
            $pad001Detail = "Audit log is accessible and operational. $retentionNote"
        }

        if ($null -ne $hasE5 -and -not $hasE5) {
            $pad001Status = 'HIGH'
            $pad001Detail += ' Without E5, audit retention is only 90 days — insufficient for most security investigations. Consider Audit Premium or log forwarding.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'PAD-001' `
            -Category 'DataProtection' `
            -Name 'Audit Log Retention and Accessibility' `
            -Status $pad001Status `
            -Detail $pad001Detail `
            -Recommendation 'Ensure audit log is enabled. Forward logs to a SIEM or Log Analytics workspace to extend retention beyond 90 days (E3) or 1 year (E5). Enable Microsoft Purview Audit Premium for critical workloads.' `
            -Reference 'https://learn.microsoft.com/purview/audit-log-retention-policies' `
            -CISControl '' -SC300Domain 'Compliance' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'PAD-001' `
            -Category 'DataProtection' `
            -Name 'Audit Log Retention and Accessibility' `
            -Status 'HIGH' `
            -Detail "Audit log API not accessible. This may indicate audit logging is disabled or permissions are insufficient. Required: AuditLog.Read.All. Error: $_" `
            -Recommendation 'Verify audit logging is enabled in the Microsoft Purview compliance portal. Grant AuditLog.Read.All to the service principal.' `
            -Reference 'https://learn.microsoft.com/purview/audit-log-enable-disable' `
            -CISControl '' -SC300Domain 'Compliance' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # PAD-002: Mailbox audit enabled (EXO check)
    # -------------------------------------------------------------------------
    $exoAvailable = $false
    try {
        $null = Get-Command Get-OrganizationConfig -ErrorAction Stop
        $exoAvailable = $true
    }
    catch {
        $exoAvailable = $false
    }

    if ($exoAvailable) {
        try {
            $orgConfig = Get-OrganizationConfig -ErrorAction Stop
            if ($orgConfig.AuditDisabled -eq $true) {
                $pad002Status = 'HIGH'
                $pad002Detail = 'Mailbox auditing is disabled at the organization level (AuditDisabled = True). Mailbox access by admins, delegates, and owners is not logged.'
            }
            else {
                $pad002Status = 'PASS'
                $pad002Detail = 'Mailbox auditing is enabled at the organization level (AuditDisabled = False).'
                if ($orgConfig.DefaultAuditSetEnabled -eq $true) {
                    $pad002Detail += ' Default audit set is active — owner, delegate, and admin actions are being audited.'
                }
            }
        }
        catch {
            $pad002Status = 'INFO'
            $pad002Detail = "EXO connected but Get-OrganizationConfig failed. Error: $_"
        }
    }
    else {
        $pad002Status = 'INFO'
        $pad002Detail = 'Exchange Online PowerShell module not connected. Mailbox audit status cannot be verified via EXO. Connect with -ConnectExchange to check this setting.'
    }

    $results.Add((New-CheckResult `
        -CheckId 'PAD-002' `
        -Category 'DataProtection' `
        -Name 'Mailbox Audit Enabled (All Users)' `
        -Status $pad002Status `
        -Detail $pad002Detail `
        -Recommendation "Verify in EXO: Get-OrganizationConfig | Select AuditDisabled. If disabled, run: Set-OrganizationConfig -AuditDisabled `$false. Ensure E3+ mailbox audit default actions cover MailItemsAccessed." `
        -Reference 'https://learn.microsoft.com/purview/audit-mailboxes' `
        -CISControl '' -SC300Domain 'Compliance' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # PAD-003: Audit log search capability (functional test)
    # -------------------------------------------------------------------------
    try {
        $searchUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1&`$select=id,activityDateTime,activityDisplayName"
        $searchResp = Invoke-MgGraphRequest -Method GET -Uri $searchUri -ErrorAction Stop

        if ($searchResp.value -and $searchResp.value.Count -gt 0) {
            $latestActivity = $searchResp.value[0].activityDateTime
            $pad003Status = 'PASS'
            $pad003Detail = "Audit log search is functional. Most recent directory audit event: $latestActivity."
        }
        else {
            $pad003Status = 'INFO'
            $pad003Detail = 'Audit log query returned no results. This may indicate audit events are not yet populated or no directory activity has occurred.'
        }
    }
    catch {
        $pad003Status = 'HIGH'
        $pad003Detail = "Audit log search failed. Required: AuditLog.Read.All. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'PAD-003' `
        -Category 'DataProtection' `
        -Name 'Audit Log Search Capability' `
        -Status $pad003Status `
        -Detail $pad003Detail `
        -Recommendation 'Ensure AuditLog.Read.All is granted. Test audit search via the Purview compliance portal. Confirm sign-in and non-interactive sign-in logs are captured.' `
        -Reference 'https://learn.microsoft.com/purview/audit-search' `
        -CISControl '' -SC300Domain 'Compliance' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # PAD-004: Insider Risk Management configured
    # -------------------------------------------------------------------------
    try {
        # IRM policies are accessible via the compliance Graph endpoint
        $irmUri = 'https://graph.microsoft.com/beta/security/cases/ediscoveryCases?$top=10'
        $irmResp = Invoke-MgGraphRequest -Method GET -Uri $irmUri -ErrorAction Stop
        $ediscoveryCases = $irmResp.value

        # Try IRM-specific endpoint
        try {
            $irmPoliciesUri = 'https://graph.microsoft.com/beta/security/insiderRiskPolicies?$top=10'
            $irmPoliciesResp = Invoke-MgGraphRequest -Method GET -Uri $irmPoliciesUri -ErrorAction Stop
            $irmPolicies = $irmPoliciesResp.value
        }
        catch {
            $irmPolicies = $null
            Write-Verbose "IRM policies endpoint not available or no permission: $_"
        }

        # Check license for E5
        try {
            $skusRespIRM = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus' `
                -ErrorAction Stop
            $hasE5ForIRM = $skusRespIRM.value | Where-Object {
                $_.skuPartNumber -match 'ENTERPRISEPREMIUM|SPE_E5|M365_F5_COMPLIANCE|INSIDER_RISK' -and
                $_.capabilityStatus -eq 'Enabled'
            }
        }
        catch {
            $hasE5ForIRM = $null
        }

        if ($null -ne $irmPolicies -and $irmPolicies.Count -gt 0) {
            $pad004Status = 'PASS'
            $pad004Detail = "$($irmPolicies.Count) Insider Risk Management policy/policies configured."
        }
        elseif ($hasE5ForIRM) {
            $pad004Status = 'MEDIUM'
            $pad004Detail = 'E5 license detected but no Insider Risk Management policies found. IRM is included in your license but not configured.'
        }
        else {
            $pad004Status = 'INFO'
            $pad004Detail = 'Insider Risk Management not configured. This feature requires E5 or Microsoft 365 E5 Compliance.'
        }
    }
    catch {
        $pad004Status = 'INFO'
        $pad004Detail = "Insider Risk Management check skipped: insufficient permissions or API not available. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'PAD-004' `
        -Category 'DataProtection' `
        -Name 'Insider Risk Management Configured' `
        -Status $pad004Status `
        -Detail $pad004Detail `
        -Recommendation 'If licensed for E5, configure Insider Risk Management policies for data theft by departing employees, data leaks, and security policy violations. Start with a targeted scope before expanding.' `
        -Reference 'https://learn.microsoft.com/purview/insider-risk-management' `
        -CISControl '' -SC300Domain 'Compliance' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    return $results
}
