#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Evaluates risky user state and risk detection activity in Entra ID Protection.

.DESCRIPTION
    Test-RiskyUsers queries the Identity Protection API for at-risk users,
    medium-risk users, recent risk detections, remediation activity trends, and
    cross-references risky users against privileged directory roles.

    All checks gracefully handle 403/license errors (requires Entra ID P2 / E5)
    and return an INFO result rather than failing hard.

.NOTES
    Required Graph Permissions : IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All,
                                  RoleManagement.Read.Directory (for RUS-005)
    License Required            : E5 / Entra ID P2 for all checks
    API Version                 : v1.0 (risk endpoints)

    Assumes New-CheckResult is dot-sourced from scripts/helpers before calling this function.
    See also (PS-only variant — no App Registration required):
        scripts/modules-psonly/IdentityProtection/Test-RiskyUsers.ps1
        Connects via: Connect-MgGraph -Scopes ... / Connect-ExchangeOnline (interactive)
        Pro : No App Registration, works with any admin account interactively
        Pro : EXO cmdlets provide native access to Exchange-specific configs
        Con : Requires interactive login — not suitable for unattended automation
        Con : Delegated permissions — bounded by the user's own role assignments
#>

function Test-RiskyUsers {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Helper: detect E5 / license-related errors
    # -------------------------------------------------------------------------
    $isLicenseError = {
        param([string]$errorMessage)
        $errorMessage -match '(403|Forbidden|LicenseValidationFailed|AadPremiumLicenseRequired|Unauthorized|premium)'
    }

    # =========================================================================
    # RUS-001: Current high-risk users (unaddressed)
    # =========================================================================
    try {
        $highRiskResponse = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'high' and riskState eq 'atRisk'&`$select=id,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime&`$top=999" `
            -Headers @{ ConsistencyLevel = 'eventual' } `
            -ErrorAction Stop
        $highRiskUsers = $highRiskResponse.value

        # Page through results
        $nextLink = $highRiskResponse.'@odata.nextLink'
        while ($nextLink) {
            $page          = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $highRiskUsers += $page.value
            $nextLink      = $page.'@odata.nextLink'
        }

        $rus001Status  = if ($highRiskUsers.Count -eq 0) { 'PASS' } else { 'CRITICAL' }
        # Anonymize: only report UPNs in AffectedObjects, count in Detail
        $affectedUpns  = @($highRiskUsers | ForEach-Object { $_.userPrincipalName })
        $rus001Detail  = "High-risk users with riskState 'atRisk': $($highRiskUsers.Count)."
        if ($highRiskUsers.Count -gt 0) {
            $rus001Detail += " These accounts have unresolved high-risk signals and can be blocked or compromised without remediation."
        }
    }
    catch {
        $errStr       = $_.ToString()
        $rus001Status = 'INFO'
        $affectedUpns = @()
        $rus001Detail = if (& $isLicenseError $errStr) {
            "Check skipped: Entra ID P2 license required for Identity Protection APIs. Error: $errStr"
        } else {
            "Check skipped: insufficient permissions. Required: IdentityRiskyUser.Read.All. Error: $errStr"
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RUS-001' `
        -Category 'IdentityProtection' `
        -Name 'High-Risk Users (Unaddressed)' `
        -Status $rus001Status `
        -Detail $rus001Detail `
        -Recommendation 'Investigate each high-risk user in Entra ID > Protection > Risky users. Confirm compromise and block, or remediate with forced password reset. Create a CA policy requiring password change for high user risk.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock' `
        -CISControl 'CIS M365 1.1.4' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects $affectedUpns))

    # =========================================================================
    # RUS-002: Medium-risk users (unaddressed, > 5 threshold)
    # =========================================================================
    try {
        $medRiskResponse = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'medium' and riskState eq 'atRisk'&`$select=id,userPrincipalName,riskLevel,riskState&`$top=999" `
            -Headers @{ ConsistencyLevel = 'eventual' } `
            -ErrorAction Stop
        $medRiskUsers = $medRiskResponse.value

        $nextLink = $medRiskResponse.'@odata.nextLink'
        while ($nextLink) {
            $page         = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $medRiskUsers += $page.value
            $nextLink     = $page.'@odata.nextLink'
        }

        $rus002Status       = if ($medRiskUsers.Count -eq 0) { 'PASS' }
                              elseif ($medRiskUsers.Count -le 5) { 'MEDIUM' }
                              else { 'HIGH' }
        $medAffectedUpns    = @($medRiskUsers | ForEach-Object { $_.userPrincipalName })
        $rus002Detail       = "Medium-risk users with riskState 'atRisk': $($medRiskUsers.Count)."
        if ($medRiskUsers.Count -gt 5) {
            $rus002Detail += " More than 5 medium-risk users indicates systematic risk detection activity that warrants investigation."
        }
    }
    catch {
        $errStr          = $_.ToString()
        $rus002Status    = 'INFO'
        $medAffectedUpns = @()
        $rus002Detail    = if (& $isLicenseError $errStr) {
            "Check skipped: Entra ID P2 license required. Error: $errStr"
        } else {
            "Check skipped: insufficient permissions. Required: IdentityRiskyUser.Read.All. Error: $errStr"
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RUS-002' `
        -Category 'IdentityProtection' `
        -Name 'Medium-Risk Users (Unaddressed)' `
        -Status $rus002Status `
        -Detail $rus002Detail `
        -Recommendation 'Review medium-risk users. Configure a CA policy requiring MFA for medium user risk. Investigate detections driving medium risk before dismissing.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks' `
        -CISControl '' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects $medAffectedUpns))

    # =========================================================================
    # RUS-003: Risk detections in the last 30 days
    # =========================================================================
    try {
        $cutoffDate    = (Get-Date).AddDays(-30).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $detectResponse = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $cutoffDate&`$select=id,riskEventType,riskLevel,riskState,detectedDateTime,userPrincipalName&`$top=999" `
            -ErrorAction Stop
        $detections    = $detectResponse.value

        $nextLink = $detectResponse.'@odata.nextLink'
        while ($nextLink) {
            $page       = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $detections += $page.value
            $nextLink   = $page.'@odata.nextLink'
        }

        $highDetections   = @($detections | Where-Object { $_.riskLevel -eq 'high' })
        $rus003Status     = if ($detections.Count -eq 0) { 'PASS' }
                            elseif ($detections.Count -le 10) { 'MEDIUM' }
                            else { 'HIGH' }
        $topTypes         = @($detections | Group-Object riskEventType | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name)($($_.Count))" })
        $rus003Detail     = "Risk detections in last 30 days: $($detections.Count) total (high: $($highDetections.Count)). " +
                            "Top detection types: $($topTypes -join ', ')."
        if ($detections.Count -gt 10) {
            $rus003Detail += " Volume exceeds threshold — review detection patterns for potential attack activity."
        }
    }
    catch {
        $errStr       = $_.ToString()
        $rus003Status = 'INFO'
        $rus003Detail = if (& $isLicenseError $errStr) {
            "Check skipped: Entra ID P2 license required. Error: $errStr"
        } else {
            "Check skipped: insufficient permissions. Required: IdentityRiskEvent.Read.All. Error: $errStr"
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RUS-003' `
        -Category 'IdentityProtection' `
        -Name 'Risk Detections — Last 30 Days' `
        -Status $rus003Status `
        -Detail $rus003Detail `
        -Recommendation 'Review risk detections in Entra ID Protection. For high-frequency detection types, investigate root cause (leaked credentials, impossible travel, etc.) and tune risk policies accordingly.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks' `
        -CISControl '' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # =========================================================================
    # RUS-004: Users remediated vs. dismissed (activity trend — INFO)
    # =========================================================================
    try {
        $remediatedResponse = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'remediated' or riskState eq 'dismissed'&`$select=id,userPrincipalName,riskState,riskLastUpdatedDateTime&`$top=999" `
            -Headers @{ ConsistencyLevel = 'eventual' } `
            -ErrorAction Stop
        $closedRiskUsers = $remediatedResponse.value

        $nextLink = $remediatedResponse.'@odata.nextLink'
        while ($nextLink) {
            $page            = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $closedRiskUsers += $page.value
            $nextLink        = $page.'@odata.nextLink'
        }

        $remediated   = @($closedRiskUsers | Where-Object { $_.riskState -eq 'remediated' })
        $dismissed    = @($closedRiskUsers | Where-Object { $_.riskState -eq 'dismissed' })
        $rus004Detail = "Remediated users: $($remediated.Count). Dismissed users: $($dismissed.Count). " +
                        "Total closed risk records: $($closedRiskUsers.Count). " +
                        "High dismiss-to-remediate ratio may indicate false-positive dismissals without investigation."
    }
    catch {
        $errStr       = $_.ToString()
        $rus004Detail = if (& $isLicenseError $errStr) {
            "Check skipped: Entra ID P2 license required. Error: $errStr"
        } else {
            "Check skipped: insufficient permissions. Required: IdentityRiskyUser.Read.All. Error: $errStr"
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RUS-004' `
        -Category 'IdentityProtection' `
        -Name 'Risk Remediation Activity (Trend)' `
        -Status 'INFO' `
        -Detail $rus004Detail `
        -Recommendation 'Monitor remediation vs. dismissal ratio. Users should be remediated (password reset) rather than dismissed unless the detection is confirmed as a false positive.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock' `
        -CISControl '' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects @()))

    # =========================================================================
    # RUS-005: Privileged users (Global Admin + other admin roles) with active risk
    # =========================================================================
    try {
        # Get all risky users at any risk level who are still atRisk
        $atRiskResponse = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'&`$select=id,userPrincipalName,riskLevel&`$top=999" `
            -Headers @{ ConsistencyLevel = 'eventual' } `
            -ErrorAction Stop
        $allAtRiskUsers = $atRiskResponse.value

        $nextLink = $atRiskResponse.'@odata.nextLink'
        while ($nextLink) {
            $page           = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            $allAtRiskUsers += $page.value
            $nextLink       = $page.'@odata.nextLink'
        }

        $riskyUserIds = @($allAtRiskUsers | ForEach-Object { $_.id })

        # Fetch privileged role members — focus on highest-impact roles
        $privilegedRoleIds = @{
            'Global Administrator'              = '62e90394-69f5-4237-9190-012177145e10'
            'Privileged Role Administrator'     = 'e8611ab8-c189-46e8-94e1-60213ab1f814'
            'Security Administrator'            = '194ae4cb-b126-40b2-bd5b-6091b380977d'
            'Exchange Administrator'            = '29232cdf-9323-42fd-ade2-1d097af3e4de'
            'SharePoint Administrator'          = 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c'
            'Conditional Access Administrator'  = 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'
            'Application Administrator'         = '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'
        }

        $riskyAdmins = [System.Collections.Generic.List[string]]::new()

        foreach ($roleName in $privilegedRoleIds.Keys) {
            try {
                $roleTemplateId = $privilegedRoleIds[$roleName]
                $membersResponse = Invoke-MgGraphRequest -Method GET `
                    -Uri "https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='$roleTemplateId')/members?`$select=id,userPrincipalName&`$top=100" `
                    -ErrorAction Stop
                $roleMembers = $membersResponse.value

                foreach ($member in $roleMembers) {
                    if ($riskyUserIds -contains $member.id) {
                        $riskyAdmins.Add("$($member.userPrincipalName) [$roleName]")
                    }
                }
            }
            catch {
                Write-Verbose "Could not enumerate role $roleName: $_"
            }
        }

        $rus005Status = if ($riskyAdmins.Count -eq 0) { 'PASS' } else { 'CRITICAL' }
        $rus005Detail = "At-risk users cross-referenced with privileged roles. Risky admins found: $($riskyAdmins.Count)."
        if ($riskyAdmins.Count -gt 0) {
            $rus005Detail += " CRITICAL: Compromised admin accounts represent the highest possible blast radius."
        }
        else {
            $rus005Detail += " No privileged role members are currently flagged as at-risk."
        }
    }
    catch {
        $errStr       = $_.ToString()
        $rus005Status = 'INFO'
        $riskyAdmins  = @()
        $rus005Detail = if (& $isLicenseError $errStr) {
            "Check skipped: Entra ID P2 license required. Error: $errStr"
        } else {
            "Check skipped: insufficient permissions. Required: IdentityRiskyUser.Read.All + RoleManagement.Read.Directory. Error: $errStr"
        }
    }

    $results.Add((New-CheckResult `
        -CheckId 'RUS-005' `
        -Category 'IdentityProtection' `
        -Name 'Privileged Users with Active Risk' `
        -Status $rus005Status `
        -Detail $rus005Detail `
        -Recommendation 'Immediately remediate any privileged users with active risk: force password reset, revoke sessions, review recent activity, and consider temporarily removing admin role assignments until cleared.' `
        -Reference 'https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock' `
        -CISControl 'CIS M365 1.1.4' `
        -SC300Domain 'Identity Risk & Protection' `
        -LicenseRequired 'E5' `
        -AffectedObjects @($riskyAdmins)))

    return $results
}
