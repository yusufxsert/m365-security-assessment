# Assessment Guide

How to prepare for, run, interpret, and act on assessment results.

---

## Pre-Assessment Checklist

Complete all items before running the assessment to avoid incomplete results or authentication failures.

- [ ] App Registration created in Entra admin center
- [ ] All required Graph API permissions assigned (see [permissions-setup.md](permissions-setup.md))
- [ ] Admin consent granted for all permissions
- [ ] Client secret or certificate created and available
- [ ] Exchange Online management role assigned to the service principal (if using `-ConnectExchange`)
- [ ] PowerShell 7.2+ installed
- [ ] Microsoft.Graph module installed: `Install-Module Microsoft.Graph -MinimumVersion 2.0.0`
- [ ] ExchangeOnlineManagement module installed (if using `-ConnectExchange`): `Install-Module ExchangeOnlineManagement`
- [ ] Output directory exists and is writable
- [ ] Test connection verified (see below)

**Test connection before running the full assessment:**

```powershell
Connect-MgGraph `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecretCredential (New-Object System.Management.Automation.PSCredential(
        "your-client-id",
        (ConvertTo-SecureString "your-secret" -AsPlainText -Force)
    ))

Get-MgContext
Get-MgUser -Top 1 -Select DisplayName
Disconnect-MgGraph
```

If the commands return data without errors, you are ready to run the full assessment.

---

## Running the Assessment

### First-time run

Run all modules to get a complete baseline assessment of the tenant.

```powershell
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret (ConvertTo-SecureString "your-secret" -AsPlainText -Force) `
    -OutputPath "./reports" `
    -Verbose
```

The `-Verbose` flag shows progress as each module runs. On first run, allow 5-15 minutes depending on tenant size and network latency.

### Scoped run (specific modules)

Use `-Modules` to target specific areas, for example after remediating CRITICAL findings:

```powershell
# Re-assess only Conditional Access and Privileged Access after remediation
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret $secret `
    -Modules @("ConditionalAccess", "PrivilegedAccess") `
    -OutputPath "./reports"
```

Available module names: `Identity`, `Authentication`, `ConditionalAccess`, `IdentityProtection`, `PrivilegedAccess`, `Governance`, `WorkloadIdentities`, `EmailSecurity`, `Endpoint`, `DataProtection`, `Monitoring`

### Scheduled run (GitHub Actions)

Store credentials as GitHub repository secrets:
- `TENANT_ID`
- `CLIENT_ID`
- `CLIENT_SECRET`

Example workflow (`.github/workflows/assessment.yml`):

```yaml
name: M365 Security Assessment

on:
  schedule:
    - cron: '0 6 * * 1'   # Every Monday at 06:00 UTC
  workflow_dispatch:        # Allow manual trigger

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install PowerShell modules
        shell: pwsh
        run: |
          Install-Module Microsoft.Graph -Force -Scope CurrentUser -MinimumVersion 2.0.0

      - name: Run assessment
        shell: pwsh
        env:
          TENANT_ID: ${{ secrets.TENANT_ID }}
          CLIENT_ID: ${{ secrets.CLIENT_ID }}
          CLIENT_SECRET: ${{ secrets.CLIENT_SECRET }}
        run: |
          $secret = ConvertTo-SecureString $env:CLIENT_SECRET -AsPlainText -Force
          .\scripts\Start-M365Assessment.ps1 `
            -TenantId $env:TENANT_ID `
            -ClientId $env:CLIENT_ID `
            -ClientSecret $secret `
            -OutputPath "./reports"

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: m365-assessment-report
          path: reports/
          retention-days: 90
```

---

## Interpreting Results

### Risk Score (0-100)

The risk score is a weighted aggregate of all findings. Higher scores indicate more severe unaddressed risk.

**Scoring weights:**

| Severity | Weight per Finding |
|---|---|
| CRITICAL | 20 points |
| HIGH | 8 points |
| MEDIUM | 3 points |
| LOW | 1 point |
| INFO / PASS | 0 points |

The raw score is normalized to a 0-100 scale based on the total number of checks that ran.

**Score thresholds:**

| Score Range | Status | Interpretation |
|---|---|---|
| 0 - 20 | Secure | Strong security posture. Address remaining findings as part of regular maintenance. |
| 21 - 40 | Good | Minor gaps present. Prioritize any CRITICAL/HIGH findings. |
| 41 - 60 | Review Needed | Multiple gaps across domains. Requires structured remediation plan. |
| 61 - 80 | Action Required | Significant risk present. Escalate to security leadership. |
| 81 - 100 | Critical Risk | Severe configuration gaps. Immediate action required. |

### Priority Matrix

Use this order when planning remediation:

1. **CRITICAL findings first** — regardless of effort. No other work takes priority.
2. **HIGH findings** — sort by effort. Address low-effort items first to reduce risk quickly.
3. **MEDIUM findings** — sort by coverage impact. Findings affecting all users before findings affecting subsets.
4. **LOW findings** — include in security roadmap, assign owners, set target quarters.

For each finding, the report provides:
- Current state (what was found)
- Recommendation (what to do)
- Reference link (CIS/CISA/Microsoft documentation)

### Common False Positives

The following checks may produce findings that do not apply to the specific tenant:

| Check | False Positive Condition | Action |
|---|---|---|
| Hybrid identity checks (HYB-xxx) | Cloud-only tenant with no on-premises AD | Suppress or document as N/A |
| E5 feature checks (IdentityProtection, Secure Score, PIM policies) | Tenant does not have E5 license | Results returned as INFO — no action needed |
| E5 Gov checks (Governance module) | Tenant does not have E5 Governance license | Results returned as INFO — no action needed |
| Break glass account detection (BGA-xxx) | Break glass accounts use a non-standard naming convention | Review manually and document |
| Guest access findings (GST-xxx) | Tenant is an internal-only tenant with guest access intentionally disabled | Document as accepted risk |
| External forwarding (MFL-xxx) | Legitimate business use of external mail forwarding | Review each forwarding rule individually |

---

## Remediation Workflow

### CRITICAL findings — Immediate escalation

1. Identify the finding and affected scope (all users, admins only, specific group).
2. Escalate to the CISO / security lead immediately.
3. Create a P1 ticket in your incident management system.
4. Implement the remediation. For CA policies: use report-only mode first, monitor for 24-48 hours, then enforce.
5. Re-run the assessment (scoped to the affected module) to confirm the finding is resolved.
6. Document the remediation date and approver in your change management system.

### HIGH findings — Security team ticket

1. Create a ticket in your project management or ITSM system for each HIGH finding.
2. Assign to the responsible team (Identity team for PIM/CA findings, Mail team for DMARC findings, etc.).
3. Set a due date within 7 days.
4. Review status in weekly security meetings.

### MEDIUM and LOW — Roadmap inclusion

1. Group related findings (e.g., all Governance findings into a "Implement Access Reviews" initiative).
2. Add to the security roadmap with a target quarter.
3. Assign an owner per initiative.
4. Track progress in quarterly security reviews.

---

## Customer Handoff Checklist

When delivering the assessment to a customer, complete the following steps before sharing the report:

- [ ] Run the full assessment internally and review all findings before the customer sees the report
- [ ] Verify that CRITICAL and HIGH findings are accurately represented (no false positives)
- [ ] Redact or mask sensitive object names if required (e.g., break glass account names, internal group names)
- [ ] Prepare a separate executive summary (1-2 page slide deck) covering: risk score, top 5 findings, recommended roadmap
- [ ] Map findings to the customer's existing security initiatives or projects where possible
- [ ] Agree on a remediation timeline before the handoff meeting
- [ ] Schedule a follow-up assessment (typically 30-90 days after remediation begins)
- [ ] Confirm how the HTML report will be stored and who has access (treat as confidential)
- [ ] Provide the customer with this assessment guide for ongoing reference

---

## Module-Specific Notes

### Identity

**What it checks:** Global user settings, blocked sign-in accounts, guest user configuration, external collaboration settings, hybrid identity configuration.

**Permissions required:** `User.Read.All`, `Directory.Read.All`, `Group.Read.All`

**Known limitations:** Hybrid identity checks (Entra Connect sync status) require `Directory.Read.All` with full directory read access. Tenants with federated domains may show additional INFO findings.

---

### Authentication

**What it checks:** Per-user MFA status, authentication method policy configuration (FIDO2, TAP, certificate-based auth), legacy authentication protocol exposure, SSPR configuration, password protection (banned passwords, smart lockout).

**Permissions required:** `Reports.Read.All`, `Policy.Read.All`, `User.Read.All`

**Known limitations:** Per-user MFA status from the registration report (`Reports.Read.All`) reflects self-service MFA registration, not enforcement state. Enforcement is assessed separately via Conditional Access checks.

---

### ConditionalAccess

**What it checks:** Policy count, enabled policies, policies in report-only mode, coverage for expected scenarios (admin MFA, all users MFA, device compliance, legacy auth block), named location configuration, alignment to Microsoft baseline templates.

**Permissions required:** `Policy.Read.All`

**Known limitations:** The framework evaluates policy configuration statically — it does not simulate policy evaluation for specific user scenarios. Complex CA policies with nested conditions may require manual verification.

---

### IdentityProtection

**What it checks:** Current risky user count and risk levels, risk detections in the last 30 days, sign-in risk policy and user risk policy configuration.

**Permissions required:** `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `Policy.Read.All`

**Known limitations:** Requires Entra ID P2 (E5) license. Returns INFO results if the tenant does not have the required license or if the permissions were not granted.

---

### PrivilegedAccess

**What it checks:** PIM enablement, eligible vs. permanent role assignments for all privileged roles, PIM role settings (MFA on activation, approval, activation window), break glass account detection, admin account hygiene (licensed correctly, dedicated admin accounts).

**Permissions required:** `RoleManagement.Read.All`, `RoleManagementPolicy.Read.AzureAD`, `User.Read.All`

**Known limitations:** Break glass account detection relies on naming convention heuristics (accounts containing "break", "glass", "emergency", "bga"). Custom naming conventions may require manual verification. `RoleManagementPolicy.Read.AzureAD` requires E5.

---

### Governance

**What it checks:** Entitlement management (access packages, catalogs), access review definitions and coverage for privileged roles and guest users, lifecycle workflow configuration, Terms of Use policies.

**Permissions required:** `EntitlementManagement.Read.All`, `AccessReview.Read.All`, `LifecycleWorkflows.Read.All`, `Agreement.Read.All`

**Known limitations:** Entitlement management, access reviews, and lifecycle workflows require Entra ID Governance (E5 Gov) license. These checks return INFO results on non-Gov tenants.

---

### WorkloadIdentities

**What it checks:** App registration credential age (secrets and certificates), app registrations without owners, unused app registrations, enterprise app user assignment settings, tenant-wide admin consent grants, OAuth permission grant scope, managed identity configuration.

**Permissions required:** `Application.Read.All`, `DelegatedPermissionGrant.ReadWrite.All`

**Known limitations:** "Unused" app registration detection is based on last sign-in activity from the audit log. Service accounts that authenticate rarely (e.g., monthly scheduled tasks) may be flagged as unused.

---

### EmailSecurity

**What it checks:** DMARC, DKIM, and SPF record configuration for all accepted domains, Defender for Office 365 anti-phishing policy settings, Safe Links policies, Safe Attachments policies, external mail forwarding rules, mail flow rules that bypass spam or malware filtering.

**Permissions required (Graph):** `Policy.Read.All`

**Permissions required (Exchange Online):** `Exchange.ManageAsApp` + `View-Only Organization Management` role

**Known limitations:** Full email security coverage requires the `-ConnectExchange` switch and Exchange Online permissions. Without Exchange connectivity, DNS-based checks (DMARC/DKIM/SPF) are still performed via Graph, but policy checks are skipped.

---

### Endpoint

**What it checks:** Intune device compliance policy count and platform coverage (Windows, macOS, iOS, Android), compliance policy settings (encryption, password, OS version), non-compliant device count, Defender for Endpoint onboarding status.

**Permissions required:** `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`

**Known limitations:** Requires Intune (Microsoft Endpoint Manager) license. Returns INFO if no compliance policies are configured or if Intune is not deployed.

---

### DataProtection

**What it checks:** Sensitivity label configuration and publishing, auto-labeling policy status, DLP policy count and enforcement mode (simulation vs. enforce), Purview audit log configuration and retention.

**Permissions required:** `InformationProtectionPolicy.Read.All`

**Known limitations:** DLP policy details require Exchange Online connectivity for full coverage. Some DLP metrics are only available via the compliance center API.

---

### Monitoring

**What it checks:** Entra ID audit log and sign-in log export configuration (diagnostic settings), Log Analytics workspace connectivity, Microsoft Sentinel data connector status, Secure Score current value and critical recommendations.

**Permissions required:** `AuditLog.Read.All`, `SecurityEvents.Read.All`, `Reports.Read.All`

**Known limitations:** Diagnostic settings checks require the App Registration to have access to the Azure subscription where Log Analytics is deployed. Sentinel connector status requires the SecurityEvents permission and appropriate RBAC on the workspace.
