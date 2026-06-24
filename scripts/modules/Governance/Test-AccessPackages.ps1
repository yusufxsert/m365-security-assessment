#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Tests Entitlement Management access package configuration.

.DESCRIPTION
    Evaluates whether Entitlement Management is in use, whether access packages
    have expiration policies and access reviews configured, checks for connected
    organizations (B2B), and assesses catalog maturity (single vs multiple catalogs).

.NOTES
    Required Permissions:
        - EntitlementManagement.Read.All

    License: Entra ID Governance / Microsoft 365 E5 (P2 minimum for Entitlement Management)
    CIS Benchmark: CIS Microsoft 365 Foundations Benchmark v3.0
    SC-300 Domain: Identity Governance
#>

function Test-AccessPackages {
    [CmdletBinding()]
    param(
        [switch]$Detailed
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # -------------------------------------------------------------------------
    # Helper: check if 403 indicates license issue
    # -------------------------------------------------------------------------
    function Test-IsLicenseError {
        param([string]$ErrorMessage)
        return ($ErrorMessage -match '(?i)(license|Forbidden|premium|P2|governance)')
    }

    # -------------------------------------------------------------------------
    # ELM-001: Entitlement Management enabled / access packages exist
    # -------------------------------------------------------------------------
    $accessPackages = $null
    try {
        $apUri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages?$top=999'
        $apResponse = Invoke-MgGraphRequest -Method GET -Uri $apUri -ErrorAction Stop
        $accessPackages = $apResponse.value
        $count = ($accessPackages | Measure-Object).Count

        # Try to detect if E5 / Governance license is likely present
        # (Heuristic: if the API responds without 403, license is in place)
        if ($count -eq 0) {
            $status = 'HIGH'
            $detail = 'Entitlement Management API is accessible but no access packages exist. If the tenant is E5-licensed, this represents ungoverned resource access.'
        }
        else {
            $status = 'PASS'
            $detail = "$count access package(s) found in Entitlement Management."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ELM-001' `
            -Category 'Governance' `
            -Name 'Entitlement Management – access packages exist' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Use Entitlement Management to govern access to Microsoft 365 groups, SharePoint sites, applications, and Teams. Create access packages for each resource bundle that requires governed access.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-overview' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }
    catch {
        $licenseMsg = if (Test-IsLicenseError $_.ToString()) {
            'Check skipped: Entra ID Governance / P2 license not available or EntitlementManagement.Read.All permission not granted.'
        } else {
            "Check skipped: insufficient permissions. Required: EntitlementManagement.Read.All."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ELM-001' `
            -Category 'Governance' `
            -Name 'Entitlement Management – access packages exist' `
            -Status 'INFO' `
            -Detail "$licenseMsg Error: $_" `
            -Recommendation 'Grant EntitlementManagement.Read.All permission. Ensure Entra ID Governance or E5 license is present.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-overview' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
        # Cannot proceed with further checks without access packages
        return $results
    }

    # -------------------------------------------------------------------------
    # ELM-002: Access packages without expiration policy
    # -------------------------------------------------------------------------
    try {
        $noExpiryPackages = [System.Collections.Generic.List[string]]::new()

        foreach ($ap in $accessPackages) {
            $apId = $ap.id
            $policyUri = "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/$apId/assignmentPolicies?`$top=50"
            try {
                $policyResponse = Invoke-MgGraphRequest -Method GET -Uri $policyUri -ErrorAction Stop
                $policies = $policyResponse.value

                foreach ($policy in $policies) {
                    $expiration = $policy.expiration
                    $noExpiry = (
                        $null -eq $expiration -or
                        $expiration.type -eq 'noExpiration' -or
                        ($expiration.type -eq 'notSpecified' -and $null -eq $expiration.duration -and $null -eq $expiration.endDateTime)
                    )
                    if ($noExpiry) {
                        $noExpiryPackages.Add("'$($ap.displayName)' (policy: '$($policy.displayName)')")
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve policies for access package $apId: $_"
            }
        }

        if ($noExpiryPackages.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$($noExpiryPackages.Count) access package assignment policies have no expiration configured: $($noExpiryPackages -join '; ')."
        }
        else {
            $status = 'PASS'
            $detail = 'All access package assignment policies have expiration configured.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ELM-002' `
            -Category 'Governance' `
            -Name 'Access packages without expiration policy' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Configure expiration on all access package assignment policies. Time-limited access reduces standing permissions and improves the hygiene of entitlement management. Recommend 90-365 days based on sensitivity.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-access-package-lifecycle-policy' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $noExpiryPackages.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ELM-002' `
            -Category 'Governance' `
            -Name 'Access packages without expiration policy' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: EntitlementManagement.Read.All. Error: $_" `
            -Recommendation 'Grant EntitlementManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-access-package-lifecycle-policy' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ELM-003: Connected organizations (B2B access packages) – INFO
    # -------------------------------------------------------------------------
    try {
        $connOrgUri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/connectedOrganizations?$top=999'
        $connOrgResponse = Invoke-MgGraphRequest -Method GET -Uri $connOrgUri -ErrorAction Stop
        $connOrgs = $connOrgResponse.value
        $count = ($connOrgs | Measure-Object).Count

        $connOrgList = $connOrgs | ForEach-Object {
            "$($_.displayName) (state: $($_.state), created: $($_.createdDateTime))"
        }

        $results.Add((New-CheckResult `
            -CheckId 'ELM-003' `
            -Category 'Governance' `
            -Name 'Connected organizations (B2B Entitlement Management)' `
            -Status 'INFO' `
            -Detail "Connected organizations: $count. $($connOrgList -join ' | ')." `
            -Recommendation 'Review connected organizations regularly. Remove organizations that no longer have an active partnership. Ensure access packages shared with external organizations have appropriate expiration and review policies.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-organization' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $connOrgList))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ELM-003' `
            -Category 'Governance' `
            -Name 'Connected organizations (B2B Entitlement Management)' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: EntitlementManagement.Read.All. Error: $_" `
            -Recommendation 'Grant EntitlementManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-organization' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ELM-004: Access packages with no review configured
    # -------------------------------------------------------------------------
    try {
        $noReviewPackages = [System.Collections.Generic.List[string]]::new()

        foreach ($ap in $accessPackages) {
            $apId = $ap.id
            $policyUri = "https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/accessPackages/$apId/assignmentPolicies?`$top=50"
            try {
                $policyResponse = Invoke-MgGraphRequest -Method GET -Uri $policyUri -ErrorAction Stop
                $policies = $policyResponse.value

                foreach ($policy in $policies) {
                    $reviewSettings = $policy.accessReviewSettings
                    if ($null -eq $reviewSettings -or $reviewSettings.isEnabled -eq $false) {
                        $noReviewPackages.Add("'$($ap.displayName)' (policy: '$($policy.displayName)')")
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve policies for access package $apId: $_"
            }
        }

        if ($noReviewPackages.Count -gt 0) {
            $status = 'MEDIUM'
            $detail = "$($noReviewPackages.Count) access package assignment policies have no access review configured: $($noReviewPackages -join '; ')."
        }
        else {
            $status = 'PASS'
            $detail = 'All access package assignment policies have access reviews configured.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ELM-004' `
            -Category 'Governance' `
            -Name 'Access packages without access review' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Enable access reviews on all access package policies, especially those granting access to sensitive resources. Configure quarterly reviews for elevated-access packages.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-access-reviews-create' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $noReviewPackages.ToArray()))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ELM-004' `
            -Category 'Governance' `
            -Name 'Access packages without access review' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: EntitlementManagement.Read.All. Error: $_" `
            -Recommendation 'Grant EntitlementManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-access-reviews-create' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    # -------------------------------------------------------------------------
    # ELM-005: Catalogs and separation of duties – INFO
    # -------------------------------------------------------------------------
    try {
        $catalogUri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement/catalogs?$top=999'
        $catalogResponse = Invoke-MgGraphRequest -Method GET -Uri $catalogUri -ErrorAction Stop
        $catalogs = $catalogResponse.value
        $catalogCount = ($catalogs | Measure-Object).Count

        $catalogList = $catalogs | ForEach-Object {
            "'$($_.displayName)' (state: $($_.state), isExternallyVisible: $($_.isExternallyVisible))"
        }

        if ($catalogCount -le 1) {
            $status = 'INFO'
            $detail = "$catalogCount catalog(s) found: $($catalogList -join ' | '). A single catalog for all resources limits delegation and separation of duties."
        }
        else {
            $status = 'PASS'
            $detail = "$catalogCount catalogs found (maturity indicator: multiple catalogs enable delegated administration). Catalogs: $($catalogList -join ' | ')."
        }

        $results.Add((New-CheckResult `
            -CheckId 'ELM-005' `
            -Category 'Governance' `
            -Name 'Entitlement Management catalogs – separation of duties' `
            -Status $status `
            -Detail $detail `
            -Recommendation 'Create separate catalogs per department, sensitivity level, or resource type. Delegate catalog ownership to resource owners. This enables separation of duties and distributed governance without requiring central IT involvement for every access package change.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-catalog-create' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects $catalogList))
    }
    catch {
        $results.Add((New-CheckResult `
            -CheckId 'ELM-005' `
            -Category 'Governance' `
            -Name 'Entitlement Management catalogs – separation of duties' `
            -Status 'INFO' `
            -Detail "Check skipped: insufficient permissions. Required: EntitlementManagement.Read.All. Error: $_" `
            -Recommendation 'Grant EntitlementManagement.Read.All permission.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-catalog-create' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
    }

    return $results
}
