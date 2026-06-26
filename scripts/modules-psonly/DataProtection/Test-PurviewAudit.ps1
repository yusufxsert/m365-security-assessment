#Requires -Version 7.0
#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits Microsoft Purview audit log configuration and IRM. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Search-UnifiedAuditLog (IPPS) and Get-IRMConfiguration
    (Exchange Online) instead of Graph API audit query endpoints.

    WHY PS-ONLY:
    The Graph Security auditLog/queries endpoint requires a POST to create a query
    job and then polling — it is designed for async bulk export, not quick assessment.
    Search-UnifiedAuditLog gives synchronous access to the same data stream and is
    the standard compliance investigation tool.

    IMPORTANT LIMITATION:
    Search-UnifiedAuditLog has a maximum lookback of 90 days for E3 licenses.
    E5 / Audit Premium extends this to 1 year (or 10 years for premium events).
    Large result sets (>5000 records) require pagination via the SessionId/SessionCommand
    parameters — this module retrieves a sampled result only.

    SEE ALSO (Graph variant):
        scripts/modules/DataProtection/Test-PurviewAudit.ps1

    Required connections:
        Connect-IPPSSession        (for Search-UnifiedAuditLog, Get-IRMConfiguration)
        Connect-MgGraph -Scopes "Organization.Read.All","AuditLog.Read.All"
                                   (for license/retention check and directory audit)

    Required roles (IPPS):
        View-Only Audit Logs  OR  Audit Logs (Exchange RBAC role)

    Required modules:
        ExchangeOnlineManagement
        Microsoft.Graph.Authentication (for license check)

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-PurviewAudit {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # PAD-001: Audit log retention and accessibility via Search-UnifiedAuditLog
    # -------------------------------------------------------------------------
    try {
        # Perform a lightweight test search — last 1 day, record type filter, top 1
        $testStart = (Get-Date).AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ss')
        $testEnd   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')

        $testResults = Search-UnifiedAuditLog `
            -StartDate $testStart `
            -EndDate $testEnd `
            -RecordType AzureActiveDirectory `
            -ResultSize 1 `
            -ErrorAction Stop

        $auditAccessible = ($testResults -ne $null)

        # Detect license tier using Graph (optional — soft fail)
        $retentionNote = 'License check skipped (Graph not connected).'
        try {
            $skuResp = Invoke-MgGraphRequest -Method GET `
                -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuPartNumber,capabilityStatus' `
                -ErrorAction Stop
            $hasE5 = $skuResp.value | Where-Object {
                $_.skuPartNumber -match 'ENTERPRISEPREMIUM|M365EDU_A5|SPE_E5|COMPLIANCE' -and
                $_.capabilityStatus -eq 'Enabled'
            }
            $retentionNote = if ($hasE5) {
                'E5 license detected — audit logs retained up to 1 year (premium events 10 years with Audit Premium).'
            } else {
                'E3 license detected — default audit retention is 90 days. Search-UnifiedAuditLog reflects this limit.'
            }
        }
        catch {
            Write-Verbose "License check via Graph failed (Graph may not be connected): $_"
        }

        if ($auditAccessible) {
            $pad001Status = 'PASS'
            $pad001Detail = "Audit log is accessible via Search-UnifiedAuditLog. $retentionNote"
        }
        else {
            $pad001Status = 'HIGH'
            $pad001Detail = "Audit log query returned no results — audit logging may be disabled or the role lacks View-Only Audit Logs. $retentionNote"
        }
    }
    catch {
        $pad001Status = 'HIGH'
        $pad001Detail = "Search-UnifiedAuditLog failed. Ensure Connect-IPPSSession is active and the account has the 'View-Only Audit Logs' Exchange RBAC role. Error: $_"
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

    # -------------------------------------------------------------------------
    # PAD-002: Mailbox audit enabled (Get-OrganizationConfig via EXO)
    # -------------------------------------------------------------------------
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
        $pad002Detail = "Get-OrganizationConfig failed. Ensure Connect-ExchangeOnline (or Connect-IPPSSession) is active. Error: $_"
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
    # PAD-003: Audit log search capability (functional test — recent event check)
    # -------------------------------------------------------------------------
    try {
        $searchStart = (Get-Date).AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ss')
        $searchEnd   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')

        $auditResults = Search-UnifiedAuditLog `
            -StartDate $searchStart `
            -EndDate $searchEnd `
            -RecordType AzureActiveDirectory `
            -ResultSize 1 `
            -ErrorAction Stop

        if ($auditResults -and $auditResults.Count -gt 0) {
            $latestEntry = $auditResults[0]
            $pad003Status = 'PASS'
            $pad003Detail = "Audit log search is functional. Most recent AzureActiveDirectory event: Operation='$($latestEntry.Operations)' at $($latestEntry.CreationDate)."
        }
        else {
            $pad003Status = 'INFO'
            $pad003Detail = 'Audit log search returned no AzureActiveDirectory events in the last 7 days. This may indicate low activity or audit logging is not capturing this record type.'
        }
    }
    catch {
        $pad003Status = 'HIGH'
        $pad003Detail = "Search-UnifiedAuditLog failed. Required role: View-Only Audit Logs. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'PAD-003' `
        -Category 'DataProtection' `
        -Name 'Audit Log Search Capability' `
        -Status $pad003Status `
        -Detail $pad003Detail `
        -Recommendation 'Ensure View-Only Audit Logs role is assigned. Test audit search via the Purview compliance portal. Confirm sign-in and non-interactive sign-in logs are captured.' `
        -Reference 'https://learn.microsoft.com/purview/audit-search' `
        -CISControl '' -SC300Domain 'Compliance' -LicenseRequired 'E3' `
        -AffectedObjects @()))

    # -------------------------------------------------------------------------
    # PAD-004: Insider Risk Management (Get-IRMConfiguration as proxy)
    # IRM in IPPS context = Information Rights Management, not Insider Risk.
    # Insider Risk Management has no PS cmdlet — this emits a guidance result.
    # -------------------------------------------------------------------------
    # Check IRM (Information Rights Management) configuration as a related data
    # protection control; emit INFO for Insider Risk Management (no cmdlet).
    try {
        $irmConfig = Get-IRMConfiguration -ErrorAction Stop
        $irmEnabled = $irmConfig.InternalLicensingEnabled -eq $true -or $irmConfig.ExternalLicensingEnabled -eq $true

        $pad004IrmDetail = if ($irmEnabled) {
            "Information Rights Management (IRM/Azure RMS) is enabled (InternalLicensing: $($irmConfig.InternalLicensingEnabled), ExternalLicensing: $($irmConfig.ExternalLicensingEnabled))."
        } else {
            "Information Rights Management (IRM/Azure RMS) is NOT enabled. Email encryption and rights protection is unavailable."
        }
    }
    catch {
        $pad004IrmDetail = "Get-IRMConfiguration failed — IRM status unknown. Error: $_"
    }

    $results.Add((New-CheckResult `
        -CheckId 'PAD-004' `
        -Category 'DataProtection' `
        -Name 'Insider Risk Management Configured' `
        -Status 'INFO' `
        -Detail "Insider Risk Management has no PowerShell cmdlet equivalent — this check requires the Purview portal or Graph API. Use the Graph variant for automated IRM policy checks: scripts/modules/DataProtection/Test-PurviewAudit.ps1. Related: $pad004IrmDetail" `
        -Recommendation 'If licensed for E5, configure Insider Risk Management policies in the Microsoft Purview compliance portal. Start with a targeted scope before expanding.' `
        -Reference 'https://learn.microsoft.com/purview/insider-risk-management' `
        -CISControl '' -SC300Domain 'Compliance' -LicenseRequired 'E5' `
        -AffectedObjects @()))

    return $results
}
