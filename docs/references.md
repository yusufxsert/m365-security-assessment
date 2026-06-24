# References

Security benchmarks, regulatory frameworks, and Microsoft documentation referenced by the assessment checks.

---

## Microsoft Documentation

### Identity & Access

- [Microsoft Entra ID documentation](https://learn.microsoft.com/en-us/entra/identity/)
- [Conditional Access overview](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview)
- [Conditional Access policy templates](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa)
- [Authentication methods in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods)
- [Microsoft Entra multifactor authentication](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks)
- [Legacy authentication and Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication)
- [Self-service password reset](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks)
- [Microsoft Entra Password Protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad)
- [Microsoft Entra Identity Protection](https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection)
- [What is Privileged Identity Management?](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure)
- [Secure access practices for administrators](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning)
- [Emergency access accounts](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access)
- [Microsoft Entra ID Governance](https://learn.microsoft.com/en-us/entra/id-governance/identity-governance-overview)
- [Entitlement management](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview)
- [Access reviews](https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview)
- [Lifecycle workflows](https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows)
- [Workload identities](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-overview)
- [App registration best practices](https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration)

### Email Security

- [Anti-phishing policies in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about)
- [Safe Links in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
- [Safe Attachments in Microsoft Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about)
- [How Sender Policy Framework (SPF) works](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure)
- [Use DKIM for email authentication](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure)
- [Use DMARC to validate email](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dmarc-configure)
- [Configure outbound spam filtering](https://learn.microsoft.com/en-us/defender-office-365/outbound-spam-policies-configure)

### Endpoint & Device Management

- [Microsoft Intune device compliance policies](https://learn.microsoft.com/en-us/mem/intune/protect/device-compliance-get-started)
- [Microsoft Defender for Endpoint overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint)

### Data Protection & Compliance

- [Sensitivity labels overview](https://learn.microsoft.com/en-us/purview/sensitivity-labels)
- [Data loss prevention overview](https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp)
- [Auditing solutions in Microsoft Purview](https://learn.microsoft.com/en-us/purview/audit-solutions-overview)
- [Microsoft Purview Audit (Premium)](https://learn.microsoft.com/en-us/purview/audit-premium)

### Monitoring & Operations

- [Microsoft Secure Score](https://learn.microsoft.com/en-us/defender-xdr/microsoft-secure-score)
- [Microsoft Sentinel overview](https://learn.microsoft.com/en-us/azure/sentinel/overview)
- [Connect Microsoft Entra data to Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/connect-azure-active-directory)
- [Microsoft Graph API reference](https://learn.microsoft.com/en-us/graph/api/overview)

---

## Security Benchmarks

### CIS Microsoft 365 Foundations Benchmark

The [CIS Microsoft 365 Foundations Benchmark](https://www.cisecurity.org/benchmark/microsoft_365) provides prescriptive guidance for establishing a secure baseline configuration of Microsoft 365. The current version is v3.0.

The benchmark is organized into the following sections:
- Account / Authentication
- Azure Active Directory (Entra ID)
- Microsoft 365 Defender
- Exchange Online
- Microsoft Teams
- SharePoint and OneDrive
- Storage

Assessment checks reference CIS control numbers in the finding detail where applicable.

### CISA Secure Cloud Business Applications (SCuBA)

The [CISA SCuBA M365 Security Configuration Baseline](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba) provides configuration baselines for federal agencies and recommended guidance for all organizations using Microsoft 365.

SCuBA baseline documents referenced:
- [AAD Baseline](https://github.com/cisagov/ScubaGear/blob/main/baselines/aad.md) — Azure Active Directory / Entra ID
- [Defender Baseline](https://github.com/cisagov/ScubaGear/blob/main/baselines/defender.md) — Microsoft Defender for Office 365
- [EXO Baseline](https://github.com/cisagov/ScubaGear/blob/main/baselines/exo.md) — Exchange Online
- [Teams Baseline](https://github.com/cisagov/ScubaGear/blob/main/baselines/teams.md) — Microsoft Teams
- [Intune Baseline](https://github.com/cisagov/ScubaGear/blob/main/baselines/intune.md) — Microsoft Intune

The [SCuBAGear tool](https://github.com/cisagov/ScubaGear) is CISA's reference implementation and was consulted during the development of this framework's checks.

### Microsoft Security Baselines

- [Microsoft security baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/overview) — previously Azure Security Benchmark
- [Zero Trust guidance for Microsoft 365](https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-overview)

### MITRE ATT&CK for Microsoft 365

- [MITRE ATT&CK Enterprise — Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
- [MITRE ATT&CK for Microsoft 365](https://attack.mitre.org/matrices/enterprise/cloud/office365/)

Key ATT&CK techniques addressed by this framework:

| Technique | ID | Assessment Coverage |
|---|---|---|
| Valid Accounts — Cloud Accounts | T1078.004 | MFA, CA, Identity Protection |
| Phishing | T1566 | Email Security, Defender for O365 |
| Forge Web Credentials | T1606 | Conditional Access, Token protection |
| Account Manipulation | T1098 | Privileged Access, PIM |
| Abuse Elevation Control Mechanism | T1548 | PIM, permanent assignments |
| Application Access Token | T1550.001 | WorkloadIdentities, OAuth consent |
| Exfiltration over Web Service | T1567 | DLP, Information Protection |
| Impair Defenses | T1562 | Audit Logs, Diagnostic Settings |

---

## Regulatory Frameworks

### ISO/IEC 27001:2022

The following ISO 27001 Annex A controls are addressed by assessment checks:

| Control | Description | Check Categories |
|---|---|---|
| A.5.15 | Access control | CAP, IAM, PIM |
| A.5.16 | Identity management | IAM, USR, HYB |
| A.5.17 | Authentication information | MFA, AMT, PWD |
| A.5.18 | Access rights | PRM, ELM, ARV |
| A.5.23 | Information security for use of cloud services | SCR, DST |
| A.8.2 | Privileged access rights | PIM, PRM, ADM |
| A.8.5 | Secure authentication | MFA, CAP, LEG |
| A.8.7 | Protection against malware | DEF, MDE |
| A.8.15 | Logging | AUD, DST |
| A.8.16 | Monitoring activities | SIM, SCR |
| A.8.20 | Networks security | CAP (compliant network locations) |

### NIST Cybersecurity Framework (CSF) 2.0

| CSF Function | CSF Category | Check Categories |
|---|---|---|
| Identify | Asset Management (ID.AM) | APP, ENT, MSI, INT |
| Protect | Identity Management (PR.AA) | IAM, MFA, CAP, PIM, AMT |
| Protect | Awareness and Training (PR.AT) | TOU |
| Protect | Data Security (PR.DS) | SLB, DLP, PAD |
| Protect | Platform Security (PR.PS) | INT, DEV, MDE |
| Detect | Continuous Monitoring (DE.CM) | AUD, DST, SIM, SCR |
| Detect | Adverse Event Analysis (DE.AE) | RUS, RPL, DEF |
| Respond | Incident Management (RS.MA) | SIM, SCR |

### GDPR Technical Measures

The following assessment checks directly support demonstrating GDPR Article 32 technical and organizational measures:

| GDPR Requirement | Check Categories |
|---|---|
| Art. 32(1)(a) — Pseudonymisation and encryption | SLB, DLP, DEV (BitLocker) |
| Art. 32(1)(b) — Confidentiality, integrity, availability | CAP, MFA, AUD |
| Art. 32(1)(c) — Restoration of access | BGA, PIM |
| Art. 32(1)(d) — Regular testing and evaluation | SCR, ARV |
| Art. 33/34 — Breach detection and notification | AUD, SIM, DST |

---

## Check-to-Reference Mapping

| Check Category | Primary Reference |
|---|---|
| MFA, Authentication Methods | CIS M365 v3.0 §1, CISA SCuBA AAD MS.AAD.3 |
| Conditional Access | CIS M365 v3.0 §1.1, CISA SCuBA AAD MS.AAD.1, MS.AAD.7 |
| Legacy Authentication | CIS M365 v3.0 §1.3, CISA SCuBA AAD MS.AAD.1.2 |
| Privileged Access / PIM | CIS M365 v3.0 §1.1.3, CISA SCuBA AAD MS.AAD.7 |
| Guest Access | CIS M365 v3.0 §2.8, CISA SCuBA AAD MS.AAD.8 |
| App Registrations | CIS M365 v3.0 §2.9, CISA SCuBA AAD MS.AAD.9 |
| Email Authentication (DMARC/DKIM/SPF) | CIS M365 v3.0 §2.2, CISA SCuBA EXO MS.EXO.1 |
| Anti-Phishing / Safe Links / Safe Attachments | CIS M365 v3.0 §2.3-2.6, CISA SCuBA Defender MS.DEFENDER |
| Audit Logs | CIS M365 v3.0 §3, CISA SCuBA AAD MS.AAD.5 |
| DLP Policies | CIS M365 v3.0 §6, NIST CSF PR.DS |
| Sensitivity Labels | Microsoft Cloud Security Benchmark, NIST CSF PR.DS |
| Intune Compliance | CIS M365 v3.0 §5, CISA SCuBA Intune MS.INTUNE |
| Identity Protection | CISA SCuBA AAD MS.AAD.2, MITRE ATT&CK T1078.004 |
| SIEM Integration | CISA SCuBA AAD MS.AAD.6, NIST CSF DE.CM |
