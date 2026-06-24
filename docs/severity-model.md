# Severity Model

This document defines the severity levels used across all assessment checks, the CheckId naming convention, and the mapping of check categories to SC-300 exam domains.

---

## Severity Levels

### CRITICAL

**Direct compromise path. Immediate action required.**

A CRITICAL finding represents a configuration gap that can be directly exploited to gain unauthorized access, escalate privileges, or cause widespread data exposure. These are not theoretical risks — they are conditions that real-world attackers actively target.

**Examples:**
- No MFA required for any user (including administrators)
- Legacy authentication protocols enabled with no blocking policy
- Zero Conditional Access policies in the tenant
- Global Administrator accounts without MFA
- All users permanently assigned Global Administrator

**SLA:** Address within 24 hours.

**Report treatment:** Red badge. Listed at the top of the findings section before all other severities. Highlighted in the executive summary. Executive attention explicitly noted.

---

### HIGH

**Significant risk. Address within 7 days.**

A HIGH finding represents a substantial security gap that increases the likelihood or impact of a breach, but does not represent an immediately exploitable path on its own. Often requires an attacker to chain it with another condition.

**Examples:**
- PIM not used — privileged roles assigned permanently instead of eligible
- No DMARC policy configured on primary domain
- No access reviews for privileged role assignments or guest accounts
- Guest users have unrestricted access to directory objects
- App registrations with client secrets that have never been rotated

**SLA:** Address within 7 days.

**Report treatment:** Orange badge. Escalate to security team for assignment and tracking.

---

### MEDIUM

**Best practice deviation. Address within 30 days.**

A MEDIUM finding indicates a departure from security best practices or a recommended hardening control that is not currently in place. The risk is real but typically requires specific conditions to be exploited.

**Examples:**
- SSPR not enabled or not enabled for all users
- App registration credentials (secrets/certificates) older than 1 year
- Missing Conditional Access policy for a specific platform or location
- Named locations not defined in the tenant
- No login page branding configured

**SLA:** Address within 30 days.

**Report treatment:** Yellow badge. Assign to the responsible team or application owner.

---

### LOW

**Hardening opportunity. Plan and schedule.**

A LOW finding is a configuration item that represents a hardening improvement or a defense-in-depth measure. Not a direct risk on its own, but contributes to a stronger overall security posture.

**Examples:**
- No Terms of Use policy configured
- Device compliance policy does not enforce BitLocker encryption
- Missing specific audit log category
- Secure Score recommendation not yet addressed
- Admin units not used to limit blast radius of administrator accounts

**SLA:** Plan within 90 days.

**Report treatment:** Blue badge. Include in security roadmap.

---

### INFO

**Inventory data, no finding.**

An INFO result is used when data was collected successfully but no finding applies — typically because the feature is not licensed, the permission was not granted, or the check is purely informational (counts, inventory).

**Examples:**
- Identity Protection checks on a tenant without E5 license
- PIM policy checks when `RoleManagementPolicy.Read.AzureAD` permission was not granted
- Listing of all permanent Global Admin assignments (count only, no threshold exceeded)
- Feature not configured because it is not applicable to the tenant type

**Report treatment:** Gray badge. Informational only. No remediation action required.

---

### PASS

**Control is in place and properly configured.**

A PASS result confirms that the specific control was evaluated and the configuration meets the expected baseline. Passed controls are listed separately in the report to provide a complete picture of the tenant's security posture.

**Report treatment:** Green badge. Listed in the "Passed Controls" section of the report.

---

## CheckId Naming Convention

Every check is assigned a unique CheckId with a category prefix and a three-digit sequential number.

### Identity & Access Management

| Prefix | Category |
|---|---|
| `IAM-xxx` | Identity & Access Management (general identity checks) |
| `USR-xxx` | User management (user settings, blocked sign-in, etc.) |
| `GST-xxx` | Guest access (guest user settings, collaboration restrictions) |
| `HYB-xxx` | Hybrid identity (Entra Connect, PHS, PTA, federation) |
| `EXT-xxx` | External identities (B2B settings, cross-tenant access) |

### Authentication

| Prefix | Category |
|---|---|
| `MFA-xxx` | MFA coverage (per-user MFA, registration, coverage gaps) |
| `AMT-xxx` | Authentication methods (FIDO2, TAP, certificate-based auth, policy config) |
| `LEG-xxx` | Legacy authentication (basic auth protocols, block policies) |
| `SSP-xxx` | Self-service password reset (SSPR enablement and configuration) |
| `PWD-xxx` | Password protection (banned passwords, smart lockout) |

### Conditional Access

| Prefix | Category |
|---|---|
| `CAP-xxx` | Conditional Access policies (policy state, configuration) |
| `GAP-xxx` | Conditional Access gaps (missing policies for expected scenarios) |
| `TPL-xxx` | Template compliance (alignment to Microsoft baseline templates) |

### Identity Protection

| Prefix | Category |
|---|---|
| `RUS-xxx` | Risky users (current risky user count, high-risk users) |
| `RPL-xxx` | Risk policies (sign-in risk policy, user risk policy configuration) |
| `WRI-xxx` | Workload risk (risky service principals) |

### Privileged Access

| Prefix | Category |
|---|---|
| `PIM-xxx` | PIM configuration (PIM enabled, role settings, activation requirements) |
| `PRM-xxx` | Permanent assignments (roles with permanent active assignment) |
| `BGA-xxx` | Break glass accounts (emergency access account detection and review) |
| `ADM-xxx` | Admin hygiene (admin account licensing, dedicated admin accounts, admin MFA) |

### Governance

| Prefix | Category |
|---|---|
| `ELM-xxx` | Entitlement management (access packages, catalogs) |
| `ARV-xxx` | Access reviews (review definitions, frequency, scope) |
| `LCW-xxx` | Lifecycle workflows (joiner/mover/leaver workflows) |
| `TOU-xxx` | Terms of Use (ToU policies, assignment) |

### Workload Identities

| Prefix | Category |
|---|---|
| `APP-xxx` | App registrations (credential age, owners, unused apps) |
| `ENT-xxx` | Enterprise apps (consent grants, user assignment required) |
| `OAU-xxx` | OAuth consent (tenant-wide admin consent, consent policies) |
| `MSI-xxx` | Managed identities (system vs user-assigned, over-permissioned identities) |

### Email Security

| Prefix | Category |
|---|---|
| `EML-xxx` | Email authentication (DMARC, DKIM, SPF per domain) |
| `DEF-xxx` | Defender for Office 365 (anti-phishing, Safe Links, Safe Attachments policies) |
| `MFL-xxx` | Mail flow (mail flow rules that bypass security, external forwarding) |

### Endpoint

| Prefix | Category |
|---|---|
| `INT-xxx` | Intune compliance (compliance policy coverage, non-compliant devices) |
| `MDE-xxx` | Defender for Endpoint (onboarding status, sensor health) |
| `DEV-xxx` | Device configuration (configuration profiles, compliance settings) |

### Data Protection

| Prefix | Category |
|---|---|
| `SLB-xxx` | Sensitivity labels (label policy, auto-labeling, label coverage) |
| `DLP-xxx` | DLP policies (policy coverage, mode — simulation vs enforce) |
| `PAD-xxx` | Purview audit (audit log retention, advanced audit) |

### Monitoring

| Prefix | Category |
|---|---|
| `AUD-xxx` | Audit logs (audit log enabled, retention settings) |
| `DST-xxx` | Diagnostic settings (Entra ID log export to Log Analytics or Event Hub) |
| `SCR-xxx` | Secure Score (current score, critical recommendations) |
| `SIM-xxx` | SIEM integration (Sentinel connector, data connector status) |

---

## SC-300 Domain Mapping

The following table maps assessment check categories to SC-300 (Microsoft Identity and Access Administrator) exam domains. Useful for study purposes or for mapping findings to certification competencies.

| Check Category | CheckId Prefixes | SC-300 Domain |
|---|---|---|
| Identity, User, Guest, Hybrid, External | IAM, USR, GST, HYB, EXT | Implement identities in Azure AD (20-25%) |
| MFA, Auth Methods, Legacy Auth, SSPR, Password | MFA, AMT, LEG, SSP, PWD | Implement authentication and access management (25-30%) |
| Conditional Access | CAP, GAP, TPL | Plan and implement Azure AD conditional access (25-30%) |
| Identity Protection | RUS, RPL, WRI | Manage Azure AD identity protection (included in access management) |
| Privileged Access | PIM, PRM, BGA, ADM | Plan and implement privileged access (15-20%) |
| Governance | ELM, ARV, LCW, TOU | Plan and implement entitlement management (15-20%) |
| Workload Identities | APP, ENT, OAU, MSI | Plan and implement workload identities (included in identity implementation) |

**Note:** Email Security, Endpoint, Data Protection, and Monitoring checks are outside the SC-300 scope but are aligned to SC-400 (Microsoft Information Protection Administrator) and SC-200 (Microsoft Security Operations Analyst) where applicable.
