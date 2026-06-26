#Requires -Version 7.0

<#
.SYNOPSIS
    Audits risky users, risk detections, and risk state remediation. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Get-MgRiskyUser -All, Get-MgRiskDetection -All, and
    Get-MgDirectoryRoleMember instead of raw Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    Microsoft.Graph.Identity.SignIns provides Get-MgRiskyUser and Get-MgRiskDetection
    as strongly-typed cmdlets with -All pagination support and -Filter parameter.
    Privileged user cross-reference uses Get-MgDirectoryRoleMember from
    Microsoft.Graph.Identity.DirectoryManagement.

    SEE ALSO (Graph variant):
        scripts/modules/IdentityProtection/Test-RiskyUsers.ps1

    Required connection:
        Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All","Directory.Read.All"

    Required scopes:
        IdentityRiskEvent.Read.All
        IdentityRiskyUser.Read.All
        Directory.Read.All  (for privileged role cross-reference)

    Required modules:
        Microsoft.Graph.Identity.SignIns
        Microsoft.Graph.Identity.DirectoryManagement

    License: Entra ID P2 (E5) required for risk data
    SC-300 Domain: Identity Protection

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
#>

function Test-RiskyUsers {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # RUS-001: Risky users at high/medium risk level
    # Get-MgRiskyUser -All with client-side risk level filter
    # -------------------------------------------------------------------------
    $allRiskyUsers = $null
    try {
        # Get all currently risky users (risk state: atRisk, confirmedCompromised)
        $allRiskyUsers = Get-MgRiskyUser `
            -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" `
            -All `
            -ErrorAction Stop
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'RUS-001' `
            -Category 'IdentityProtection' `
            -Name 'High/Medium Risk Users' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or Entra ID P2 not licensed. Required: IdentityRiskyUser.Read.All + P2. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All". Risk data requires Entra ID P2 / E5 license.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @()))
        return $results
    }

    $highRiskUsers   = @($allRiskyUsers | Where-Object { $_.RiskLevel -eq 'high' })
    $mediumRiskUsers = @($allRiskyUsers | Where-Object { $_.RiskLevel -eq 'medium' })

    if ($highRiskUsers.Count -gt 0) {
        $rus001Status = 'CRITICAL'
        $rus001Detail = "HIGH-RISK users with unresolved risk state: $($highRiskUsers.Count). These accounts show indicators of compromise and require immediate investigation."
    }
    elseif ($mediumRiskUsers.Count -gt 5) {
        $rus001Status = 'HIGH'
        $rus001Detail = "No high-risk users, but $($mediumRiskUsers.Count) medium-risk users have unresolved risk."
    }
    elseif ($mediumRiskUsers.Count -gt 0) {
        $rus001Status = 'MEDIUM'
        $rus001Detail = "$($mediumRiskUsers.Count) medium-risk user(s) with unresolved risk state."
    }
    else {
        $rus001Status = 'PASS'
        $rus001Detail = "No users at high or medium risk level (atRisk or confirmedCompromised state)."
    }

    $results.Add((New-CheckResult `
        -CheckId 'RUS-001' `
        -Category 'IdentityProtection' `
        -Name 'High/Medium Risk Users' `
        -Status $rus001Status `
        -Detail "$rus001Detail Total active risky users: $($allRiskyUsers.Count)." `
        -Recommendation 'Investigate risky users in Entra ID Protection. For high-risk users, require password reset + MFA confirmation. For confirmed compromised accounts, revoke sessions and reset credentials immediately.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock' `
        -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
        -AffectedObjects @($highRiskUsers | Select-Object -First 20 | ForEach-Object { $_.UserPrincipalName })))

    # -------------------------------------------------------------------------
    # RUS-002: Confirmed compromised accounts (riskState = confirmedCompromised)
    # -------------------------------------------------------------------------
    $confirmedCompromised = @($allRiskyUsers | Where-Object { $_.RiskState -eq 'confirmedCompromised' })

    $results.Add((New-CheckResult `
        -CheckId 'RUS-002' `
        -Category 'IdentityProtection' `
        -Name 'Confirmed Compromised Accounts' `
        -Status $(if ($confirmedCompromised.Count -gt 0) { 'CRITICAL' } else { 'PASS' }) `
        -Detail $(if ($confirmedCompromised.Count -gt 0) {
                    "CRITICAL: $($confirmedCompromised.Count) account(s) are in 'confirmedCompromised' risk state. These require immediate action: revoke all sessions, reset credentials, review audit log for malicious activity."
                } else {
                    "No accounts in confirmedCompromised risk state."
                }) `
        -Recommendation 'For confirmedCompromised accounts: (1) Immediately revoke refresh tokens via revokeSignInSessions, (2) Reset password, (3) Disable the account during investigation, (4) Review audit log for lateral movement or data exfiltration.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock' `
        -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
        -AffectedObjects @($confirmedCompromised | Select-Object -First 20 | ForEach-Object { $_.UserPrincipalName })))

    # -------------------------------------------------------------------------
    # RUS-003: Risk detection types in last 30 days
    # Get-MgRiskDetection -All
    # -------------------------------------------------------------------------
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')

        $riskDetections = Get-MgRiskDetection `
            -Filter "detectedDateTime ge $thirtyDaysAgo" `
            -All `
            -ErrorAction Stop

        $detectionsByType = $riskDetections |
            Group-Object -Property RiskEventType |
            Sort-Object Count -Descending |
            Select-Object -First 10

        $topDetections = $detectionsByType | ForEach-Object { "$($_.Name): $($_.Count)" }

        $highRiskDetections = @($riskDetections | Where-Object { $_.RiskLevel -eq 'high' })
        $unfixedDetections  = @($riskDetections | Where-Object { $_.RiskState -notin @('remediated', 'dismissed', 'confirmedSafe') })

        $results.Add((New-CheckResult `
            -CheckId 'RUS-003' `
            -Category 'IdentityProtection' `
            -Name 'Risk Detection Types (Last 30 Days)' `
            -Status $(if ($highRiskDetections.Count -gt 0) { 'HIGH' } elseif ($riskDetections.Count -gt 20) { 'MEDIUM' } else { 'INFO' }) `
            -Detail "Risk detections in last 30 days: $(($riskDetections | Measure-Object).Count) total. High severity: $($highRiskDetections.Count). Unresolved: $($unfixedDetections.Count). Top types: $($topDetections -join '; ')." `
            -Recommendation 'Review high-severity detection types. Focus on: anonymizedIPAddress, unfamiliarFeatures, maliciousIPAddress, impossibleTravel, passwordSpray. These are highest-fidelity indicators of compromise.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'RUS-003' `
            -Category 'IdentityProtection' `
            -Name 'Risk Detection Types (Last 30 Days)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions or P2 not licensed. Required: IdentityRiskEvent.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All". Risk detection data requires Entra ID P2.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # RUS-004: Risky privileged users (cross-reference with privileged roles)
    # Get-MgDirectoryRoleMember for Global Admin + Privileged Role Admin
    # -------------------------------------------------------------------------
    try {
        # Get privileged role IDs — use well-known template IDs (stable across tenants)
        # Global Administrator: 62e90394-69f5-4237-9190-012177145e10
        # Privileged Role Administrator: e8611ab8-c189-46e8-94e1-60213ab1f814
        # Security Administrator: 194ae4cb-b126-40b2-bd5b-6091b380977d
        # User Account Administrator: fe930be7-5e62-47db-91af-98c3a49a38b1

        $privilegedRoleTemplateIds = @(
            '62e90394-69f5-4237-9190-012177145e10',  # Global Administrator
            'e8611ab8-c189-46e8-94e1-60213ab1f814',  # Privileged Role Administrator
            '194ae4cb-b126-40b2-bd5b-6091b380977d',  # Security Administrator
            'fe930be7-5e62-47db-91af-98c3a49a38b1'   # User Account Administrator
        )

        $privilegedUserIds = [System.Collections.Generic.HashSet[string]]::new()

        $directoryRoles = Get-MgDirectoryRole -All -ErrorAction Stop
        foreach ($role in ($directoryRoles | Where-Object { $_.RoleTemplateId -in $privilegedRoleTemplateIds })) {
            $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                [void]$privilegedUserIds.Add($m.Id)
            }
        }

        $riskyPrivilegedUsers = @($allRiskyUsers | Where-Object {
            $_.Id -in $privilegedUserIds -or
            $_.UserPrincipalName -in ($privilegedUserIds | ForEach-Object { $_ })
        })

        # Better match: cross by Id
        if ($allRiskyUsers.Count -gt 0 -and $privilegedUserIds.Count -gt 0) {
            $riskyPrivilegedUsers = @($allRiskyUsers | Where-Object { $privilegedUserIds.Contains($_.Id) })
        }

        if ($riskyPrivilegedUsers.Count -gt 0) {
            $rus004Status = 'CRITICAL'
            $rus004Detail = "CRITICAL: $($riskyPrivilegedUsers.Count) privileged user(s) (Global Admin, Security Admin, PRA, UAA) have an active risk state. Compromised privileged accounts are the highest-risk scenario."
        }
        else {
            $rus004Status = 'PASS'
            $rus004Detail = "No privileged users with active risk state found. $($privilegedUserIds.Count) privileged accounts checked across 4 admin role categories."
        }

        $results.Add((New-CheckResult `
            -CheckId 'RUS-004' `
            -Category 'IdentityProtection' `
            -Name 'Risky Privileged Users' `
            -Status $rus004Status `
            -Detail $rus004Detail `
            -Recommendation 'Immediately revoke sessions and reset credentials for any privileged user with active risk. Consider temporarily disabling the account. Review all actions taken with the account in the last 30 days via the audit log.' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @($riskyPrivilegedUsers | ForEach-Object { $_.UserPrincipalName })))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'RUS-004' `
            -Category 'IdentityProtection' `
            -Name 'Risky Privileged Users' `
            -Status 'INFO' `
            -Detail "Check skipped: API error. Required: IdentityRiskyUser.Read.All + Directory.Read.All. Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All","Directory.Read.All".' `
            -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk' `
            -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # RUS-005: Risk state age — stale risky users (risk unresolved > 30 days)
    # -------------------------------------------------------------------------
    $staleThreshold   = (Get-Date).AddDays(-30)
    $staleRiskyUsers  = @($allRiskyUsers | Where-Object {
        $_.RiskLastUpdatedDateTime -and
        [datetime]$_.RiskLastUpdatedDateTime -lt $staleThreshold
    })

    if ($staleRiskyUsers.Count -gt 0) {
        $rus005Status = 'MEDIUM'
        $rus005Detail = "$($staleRiskyUsers.Count) risky user(s) have had unresolved risk for more than 30 days. Long-outstanding risk states indicate the risk remediation process is not functioning effectively."
    }
    else {
        $rus005Status = 'PASS'
        $rus005Detail = "No risky users with unresolved risk older than 30 days."
    }

    $results.Add((New-CheckResult `
        -CheckId 'RUS-005' `
        -Category 'IdentityProtection' `
        -Name 'Stale Risky Users (Unresolved > 30 Days)' `
        -Status $rus005Status `
        -Detail $rus005Detail `
        -Recommendation 'Establish a risk remediation SLA (e.g., high risk: 24h, medium risk: 7 days). Automate remediation via risk-based Conditional Access policies that require password reset or MFA for risky users.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock' `
        -CISControl '' -SC300Domain 'Identity Protection' -LicenseRequired 'E5' `
        -AffectedObjects @($staleRiskyUsers | Select-Object -First 20 | ForEach-Object { $_.UserPrincipalName })))

    return $results
}
