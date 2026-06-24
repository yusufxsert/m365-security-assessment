# M365 Security Assessment Framework

![PowerShell](https://img.shields.io/badge/PowerShell-7.2%2B-5391FE?style=flat&logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph%20API-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Last Updated](https://img.shields.io/badge/Updated-2025-blue?style=flat)

Professional Microsoft 365 security assessment framework covering all IAM and security domains. Generates customer-ready HTML reports with severity ratings aligned to **CIS Microsoft 365 Foundations Benchmark v3.0** and **CISA SCuBA M365 Security Configuration Baseline**.

---

## Assessment Coverage

| Module | Checks | License Requirement | Key Focus |
|---|---|---|---|
| **Identity** | ~15 | E3 | Users, guests, hybrid identity, external collaboration |
| **Authentication** | ~12 | E3/E5 | MFA coverage, authentication methods, legacy auth, SSPR, password protection |
| **ConditionalAccess** | ~18 | E3 | Policy coverage, gaps, baseline template compliance |
| **IdentityProtection** | ~8 | E5 | Risky users, risk detections, risk-based policies |
| **PrivilegedAccess** | ~14 | E5 | PIM configuration, permanent role assignments, break glass accounts, admin hygiene |
| **Governance** | ~10 | E5 Gov | Access packages, access reviews, lifecycle workflows, Terms of Use |
| **WorkloadIdentities** | ~10 | E3 | App registrations, enterprise apps, OAuth consent, managed identities |
| **EmailSecurity** | ~12 | E3/E5 | DMARC/DKIM/SPF, anti-phishing, Safe Links, Safe Attachments, mail flow |
| **Endpoint** | ~10 | E3/E5 | Intune compliance, device enrollment, Defender for Endpoint |
| **DataProtection** | ~8 | E3/E5 | Sensitivity labels, DLP policies, Purview audit |
| **Monitoring** | ~10 | E3/E5 | Audit logs, diagnostic settings, Secure Score, SIEM integration |

**Total: 120+ security checks across 11 domains**

---

## Requirements

- **PowerShell 7.2+** (Windows, macOS, or Linux)
- **Microsoft.Graph PowerShell SDK** v2.x
- **ExchangeOnlineManagement** module (required for `-ConnectExchange`)
- An **App Registration** in Entra ID with the required API permissions

```powershell
# Install required modules
Install-Module Microsoft.Graph -Scope CurrentUser -MinimumVersion 2.0.0
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

See [docs/permissions-setup.md](docs/permissions-setup.md) for the full App Registration guide.

---

## Quick Start

### 1. Clone the repository

```powershell
git clone https://github.com/yusufxsert/m365-security-assessment.git
cd m365-security-assessment
```

### 2. Install dependencies

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -MinimumVersion 2.0.0
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### 3. Create App Registration

Follow the guide in [docs/permissions-setup.md](docs/permissions-setup.md) to:
- Create the App Registration in Entra admin center
- Assign all required Graph API permissions
- Grant admin consent
- Create a client secret or upload a certificate

### 4. Run the assessment

**Basic assessment (all modules):**

```powershell
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-app-client-id" `
    -ClientSecret (ConvertTo-SecureString "your-secret" -AsPlainText -Force) `
    -OutputPath "./reports"
```

**Run specific modules only:**

```powershell
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-app-client-id" `
    -ClientSecret $secret `
    -Modules @("ConditionalAccess", "PrivilegedAccess") `
    -OutputPath "./reports"
```

**With Exchange Online (required for email security checks):**

```powershell
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-app-client-id" `
    -ClientSecret $secret `
    -ConnectExchange `
    -OutputPath "./reports"
```

**Using a certificate instead of a client secret (recommended for production):**

```powershell
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-app-client-id" `
    -CertificateThumbprint "ABCDEF1234567890" `
    -OutputPath "./reports"
```

---

## Output Files

After the assessment completes, the following files are written to the specified output path:

| File | Format | Purpose |
|---|---|---|
| `M365Assessment_[TenantId]_[Date].html` | HTML | Executive-ready report, open in any browser |
| `M365Assessment_[TenantId]_[Date].json` | JSON | Machine-readable export for further processing |

---

## Report Structure

The HTML report is self-contained (no external dependencies) and includes:

- **Executive Summary** — Overall risk score (0-100), critical/high finding counts, assessment metadata (tenant, date, modules run)
- **Risk Score Gauge** — Visual indicator with thresholds: Secure (0-30), Review Needed (31-60), Action Required (61-100)
- **Findings by Category** — Collapsible sections per module with color-coded severity badges
- **Finding Detail** — Per-check: CheckId, title, severity, current state, recommendation, and reference links
- **Passed Controls** — Full list of controls confirmed in place
- **Module Coverage** — Which modules ran and their status (completed, skipped, error)

---

## Required Graph API Permissions (Summary)

| Permission | Type | Purpose |
|---|---|---|
| `Directory.Read.All` | Application | Users, groups, devices, directory objects |
| `Policy.Read.All` | Application | Conditional Access, auth method policies |
| `RoleManagement.Read.All` | Application | Role assignments, PIM |
| `AuditLog.Read.All` | Application | Sign-in logs, audit events |
| `Reports.Read.All` | Application | MFA registration, usage reports |
| `IdentityRiskyUser.Read.All` | Application | Risky users (E5) |
| `IdentityRiskEvent.Read.All` | Application | Risk detections (E5) |
| `Application.Read.All` | Application | App registrations, service principals |
| `SecurityEvents.Read.All` | Application | Secure Score, security alerts |
| `DeviceManagementConfiguration.Read.All` | Application | Intune compliance policies |

Full permissions list with license requirements: [docs/permissions-setup.md](docs/permissions-setup.md)

---

## Severity Model

| Severity | Color | Description | Response SLA |
|---|---|---|---|
| **CRITICAL** | Red | Direct compromise path. Immediate action required. | 24 hours |
| **HIGH** | Orange | Significant risk. Escalate to security team. | 7 days |
| **MEDIUM** | Yellow | Best practice deviation. Assign to responsible owner. | 30 days |
| **LOW** | Blue | Hardening opportunity. Plan and schedule. | 90 days |
| **INFO** | Gray | Inventory data, feature disabled, or license not present. | N/A |
| **PASS** | Green | Control is in place and properly configured. | N/A |

Full severity model with examples and CheckId naming conventions: [docs/severity-model.md](docs/severity-model.md)

---

## Documentation

| Document | Description |
|---|---|
| [docs/permissions-setup.md](docs/permissions-setup.md) | App Registration and Graph API permissions guide |
| [docs/severity-model.md](docs/severity-model.md) | Severity levels, CheckId conventions, SC-300 domain mapping |
| [docs/assessment-guide.md](docs/assessment-guide.md) | How to run, interpret, and act on assessment results |
| [docs/references.md](docs/references.md) | CIS, CISA SCuBA, MITRE ATT&CK, and regulatory references |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

---

## Security Notes

- **All access is READ-ONLY.** No configuration changes are made to the tenant.
- **No external data transmission.** All data stays within your environment. No telemetry, no callbacks.
- **Credentials are never stored.** Secrets and tokens are kept in memory only for the duration of the assessment.
- **Report sensitivity.** The generated report may contain sensitive tenant configuration data, user counts, and security gaps. Handle and distribute accordingly — treat it as confidential.
- **Audit log visibility.** All Microsoft Graph API calls are visible in the Entra ID audit log under the App Registration's service principal.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for significant changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/add-new-check`
3. Follow the existing CheckId naming conventions (see [docs/severity-model.md](docs/severity-model.md))
4. Submit a pull request with a clear description of the new check and its reference source

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Aligned with: CIS Microsoft 365 Foundations Benchmark v3.0 | CISA SCuBA M365 Security Configuration Baseline | Microsoft Security Baselines*
