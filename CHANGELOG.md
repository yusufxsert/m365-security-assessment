# Changelog

All notable changes to the M365 Security Assessment Framework are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.0.0] - 2025-XX-XX

### Added

- Initial release of the M365 Security Assessment Framework
- Full assessment coverage across 11 security domains: Identity, Authentication, ConditionalAccess, IdentityProtection, PrivilegedAccess, Governance, WorkloadIdentities, EmailSecurity, Endpoint, DataProtection, Monitoring
- 120+ security checks with unique CheckId naming convention
- HTML report generation with executive summary, risk score gauge, and per-category findings
- JSON export for machine-readable results and pipeline integration
- Severity model: CRITICAL, HIGH, MEDIUM, LOW, INFO, PASS
- Weighted risk score (0-100) with labeled thresholds
- GitHub Actions workflow for scheduled assessments
- App-only (client credentials) authentication via Microsoft.Graph PowerShell SDK v2
- Certificate-based authentication support
- Exchange Online integration for email security checks (`-ConnectExchange`)
- Module-scoped runs via `-Modules` parameter
- CIS Microsoft 365 Foundations Benchmark v3.0 alignment
- CISA Secure Cloud Business Applications (SCuBA) M365 alignment
- MITRE ATT&CK for M365 technique mapping
- SC-300 exam domain mapping for all check categories
- Documentation: permissions setup guide, severity model, assessment guide, references
- MIT License

### Assessment Checks Added

**Identity**
- IAM-001: External collaboration settings
- USR-001: Blocked sign-in accounts review
- GST-001: Guest access permissions level
- GST-002: Guest invite restrictions
- HYB-001: Hybrid identity sync status
- EXT-001: Cross-tenant access settings

**Authentication**
- MFA-001: Authentication methods policy state
- MFA-002: MFA registration coverage (all users)
- MFA-003: Admin MFA registration coverage
- LEG-001: Legacy authentication block policy
- LEG-002: Basic authentication status
- SSP-001: SSPR enablement
- SSP-002: SSPR scope (all users vs selected)
- PWD-001: Password protection policy
- PWD-002: Smart lockout configuration

**Conditional Access**
- CAP-001: Total CA policy count
- CAP-002: Policies in report-only mode
- CAP-003: Policies targeting all users
- GAP-001: Admin MFA policy present
- GAP-002: All users MFA policy present
- GAP-003: Legacy auth block policy present
- GAP-004: Device compliance requirement policy
- GAP-005: Sign-in risk policy via CA
- GAP-006: User risk policy via CA
- TPL-001: Named locations defined

**Identity Protection**
- RUS-001: Current high-risk users count
- RUS-002: Risky users not remediated (>7 days)
- RPL-001: Sign-in risk policy configuration
- RPL-002: User risk policy configuration

**Privileged Access**
- PIM-001: PIM enabled (Entra ID P2)
- PRM-001: Permanent Global Administrator count
- PRM-002: Privileged roles with permanent assignments
- BGA-001: Break glass accounts detected
- BGA-002: Break glass accounts excluded from CA policies
- ADM-001: Admin accounts with E5/P2 license
- ADM-002: Admin accounts dedicated (not used for normal work)

**Governance**
- ELM-001: Entitlement management catalogs
- ARV-001: Access reviews for privileged roles
- ARV-002: Access reviews for guest users
- LCW-001: Lifecycle workflows configured
- TOU-001: Terms of Use policies

**Workload Identities**
- APP-001: App registrations with expired credentials
- APP-002: App registrations with credentials older than 1 year
- APP-003: App registrations without owners
- ENT-001: Enterprise apps requiring user assignment
- OAU-001: Tenant-wide admin consent workflow
- MSI-001: Managed identities inventory

**Email Security**
- EML-001: DMARC record presence and policy
- EML-002: DKIM configuration for accepted domains
- EML-003: SPF record configuration
- DEF-001: Anti-phishing policy (impersonation protection)
- DEF-002: Safe Links policy
- DEF-003: Safe Attachments policy
- MFL-001: Mail flow rules bypassing spam filter
- MFL-002: External email auto-forwarding

**Endpoint**
- INT-001: Device compliance policies configured
- INT-002: Windows compliance policy present
- INT-003: Non-compliant device percentage
- MDE-001: Defender for Endpoint onboarding status
- DEV-001: Device enrollment restrictions

**Data Protection**
- SLB-001: Sensitivity labels configured
- SLB-002: Sensitivity label policies published
- DLP-001: DLP policies configured
- DLP-002: DLP policies in enforce mode
- PAD-001: Unified audit log enabled
- PAD-002: Purview Audit (Premium) retention

**Monitoring**
- AUD-001: Entra ID diagnostic settings configured
- DST-001: Sign-in logs exported to Log Analytics
- DST-002: Audit logs exported to Log Analytics
- SCR-001: Microsoft Secure Score current value
- SIM-001: Microsoft Sentinel Entra ID connector status

---

[Unreleased]: https://github.com/yusufxsert/m365-security-assessment/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/yusufxsert/m365-security-assessment/releases/tag/v1.0.0
