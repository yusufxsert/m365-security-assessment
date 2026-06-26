#Requires -Version 7.0

<#
.SYNOPSIS
    Tests Entitlement Management access package configuration. PS-ONLY variant.

.DESCRIPTION
    PS-ONLY VARIANT — uses Microsoft.Graph.Identity.Governance cmdlets instead of
    raw Invoke-MgGraphRequest calls.

    WHY PS-ONLY:
    The Microsoft.Graph.Identity.Governance module wraps the same Graph API endpoints
    but provides strongly-typed output objects, automatic pagination, and
    PowerShell-idiomatic error handling. Avoids manual pagination loops and URI
    string construction for the /identityGovernance/entitlementManagement path.

    SEE ALSO (Graph variant):
        scripts/modules/Governance/Test-AccessPackages.ps1

    Required connection:
        Connect-MgGraph -Scopes "EntitlementManagement.Read.All"

    Required scopes:
        EntitlementManagement.Read.All

    Required modules:
        Microsoft.Graph.Identity.Governance

    License: Entra ID Governance / Microsoft 365 E5 (P2 minimum)
    SC-300 Domain: Identity Governance

.NOTES
    All findings are returned as PSCustomObject via New-CheckResult.
    The function is read-only and makes no changes to tenant configuration.
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
        $accessPackages = Get-MgEntitlementManagementAccessPackage -All -ErrorAction Stop
        $count = ($accessPackages | Measure-Object).Count

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
            'Check skipped: insufficient permissions. Required: EntitlementManagement.Read.All.'
        }

        $results.Add((New-CheckResult `
            -CheckId 'ELM-001' `
            -Category 'Governance' `
            -Name 'Entitlement Management – access packages exist' `
            -Status 'INFO' `
            -Detail "$licenseMsg Error: $_" `
            -Recommendation 'Connect-MgGraph -Scopes "EntitlementManagement.Read.All". Ensure Entra ID Governance or E5 license is present.' `
            -Reference 'https://learn.microsoft.com/entra/id-governance/entitlement-management-overview' `
            -CISControl '' `
            -SC300Domain 'Identity Governance' `
            -LicenseRequired 'E5' `
            -AffectedObjects @()))
        return $results
    }

    # -------------------------------------------------------------------------
    # ELM-002: Access packages without expiration policy
    # -------------------------------------------------------------------------
    try {
        $noExpiryPackages = [System.Collections.Generic.List[string]]::new()

        # Get-MgEntitlementManagementAccessPackageAssignmentPolicy requires -AccessPackageId
        # in SDK v2 — collect per package to avoid mandatory parameter prompt.
        $allPolicies = [System.Collections.Generic.List[object]]::new()
        foreach ($ap in $accessPackages) {
            try {
                $pkgPolicies = Get-MgEntitlementManagementAccessPackageAssignmentPolicy `
                    -AccessPackageId $ap.Id -All -ErrorAction SilentlyContinue
                foreach ($p in $pkgPolicies) { $allPolicies.Add($p) }
            } catch {}
        }

        foreach ($ap in $accessPackages) {
            $apPolicies = @($allPolicies | Where-Object { $_.AccessPackageId -eq $ap.Id })

            foreach ($policy in $apPolicies) {
                $expiration = $policy.Expiration
                $noExpiry = (
                    $null -eq $expiration -or
                    $expiration.Type -eq 'noExpiration' -or
                    ($expiration.Type -eq 'notSpecified' -and $null -eq $expiration.Duration -and $null -eq $expiration.EndDateTime)
                )
                if ($noExpiry) {
                    $noExpiryPackages.Add("'$($ap.DisplayName)' (policy: '$($policy.DisplayName)')")
                }
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
            -Recommendation 'Configure expiration on all access package assignment policies. Time-limited access reduces standing permissions. Recommend 90-365 days based on sensitivity.' `
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
        $connOrgs  = Get-MgEntitlementManagementConnectedOrganization -All -ErrorAction Stop
        $count     = ($connOrgs | Measure-Object).Count
        $connOrgList = $connOrgs | ForEach-Object {
            "$($_.DisplayName) (state: $($_.State), created: $($_.CreatedDateTime))"
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
        # Re-use allPolicies retrieved in ELM-002 if available; collect per package if not
        $policiesForReview = if ($allPolicies -and $allPolicies.Count -gt 0) { $allPolicies } else {
            $tmp = [System.Collections.Generic.List[object]]::new()
            foreach ($ap in $accessPackages) {
                try {
                    $pkgPolicies = Get-MgEntitlementManagementAccessPackageAssignmentPolicy `
                        -AccessPackageId $ap.Id -All -ErrorAction SilentlyContinue
                    foreach ($p in $pkgPolicies) { $tmp.Add($p) }
                } catch {}
            }
            $tmp
        }

        foreach ($ap in $accessPackages) {
            $apPolicies = @($policiesForReview | Where-Object { $_.AccessPackageId -eq $ap.Id })

            foreach ($policy in $apPolicies) {
                $reviewSettings = $policy.AccessReviewSettings
                if ($null -eq $reviewSettings -or $reviewSettings.IsEnabled -eq $false) {
                    $noReviewPackages.Add("'$($ap.DisplayName)' (policy: '$($policy.DisplayName)')")
                }
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
        $catalogs      = Get-MgEntitlementManagementCatalog -All -ErrorAction Stop
        $catalogCount  = ($catalogs | Measure-Object).Count
        $catalogList   = $catalogs | ForEach-Object {
            "'$($_.DisplayName)' (state: $($_.State), isExternallyVisible: $($_.IsExternallyVisible))"
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
            -Recommendation 'Create separate catalogs per department, sensitivity level, or resource type. Delegate catalog ownership to resource owners to enable separation of duties.' `
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
