# App Registration & Permissions Setup

This guide walks through creating the Entra ID App Registration required to run the M365 Security Assessment Framework.

---

## Overview

The framework authenticates to Microsoft Graph using **application permissions** (app-only, no interactive sign-in required). This allows it to run unattended — for example, in a GitHub Actions pipeline or as a scheduled task.

You need:
1. An App Registration in Entra ID
2. All required Graph API permissions assigned and admin-consented
3. Either a client secret or a certificate to authenticate

---

## Step 1: Create the App Registration

1. Open the [Entra admin center](https://entra.microsoft.com) and sign in as a Global Administrator or Application Administrator.
2. Navigate to **Identity > Applications > App registrations**.
3. Click **New registration**.
4. Configure the registration:
   - **Name:** `M365-Security-Assessment` (or your preferred name)
   - **Supported account types:** `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI:** Leave blank for now (not required for app-only auth)
5. Click **Register**.
6. After creation, note the following values from the **Overview** page — you will need them when running the assessment:
   - **Application (client) ID**
   - **Directory (tenant) ID**

---

## Step 2: Assign Graph API Permissions

1. In your App Registration, go to **API permissions**.
2. Click **Add a permission**.
3. Select **Microsoft Graph**.
4. Select **Application permissions** (not Delegated — the framework runs without a signed-in user).
5. Add each permission listed in the table below.
6. Repeat for all permissions.

After adding all permissions, click **Grant admin consent for [your tenant]** and confirm. All permissions must show a green checkmark with **Granted for [tenant]** status.

### Complete Permissions Table

| Permission | Type | Required For | Min. License |
|---|---|---|---|
| `User.Read.All` | Application | User identity checks, MFA status per-user | E3 |
| `Group.Read.All` | Application | Group membership, dynamic groups | E3 |
| `Directory.Read.All` | Application | Directory objects, devices, organizational settings | E3 |
| `Policy.Read.All` | Application | Conditional Access policies, authentication method policies, authorization policies | E3 |
| `RoleManagement.Read.All` | Application | Directory role assignments, PIM-eligible and active assignments | E3 |
| `AuditLog.Read.All` | Application | Sign-in logs, audit events, provisioning logs | E3 |
| `Reports.Read.All` | Application | MFA registration report, credential user registration details | E3 |
| `Application.Read.All` | Application | App registrations, service principals, enterprise apps | E3 |
| `DelegatedPermissionGrant.ReadWrite.All` | Application | OAuth 2.0 permission grants (consent analysis) | E3 |
| `Agreement.Read.All` | Application | Terms of Use policies | E3 |
| `DeviceManagementConfiguration.Read.All` | Application | Intune device compliance policies, configuration profiles | E3 |
| `DeviceManagementManagedDevices.Read.All` | Application | Intune managed devices inventory | E3 |
| `InformationProtectionPolicy.Read.All` | Application | Sensitivity labels, MIP policies | E3 |
| `IdentityRiskyUser.Read.All` | Application | Risky users list from Identity Protection | **E5** |
| `IdentityRiskEvent.Read.All` | Application | Risk detections from Identity Protection | **E5** |
| `RoleManagementPolicy.Read.AzureAD` | Application | PIM role management policies (activation rules, approval, MFA on activation) | **E5** |
| `EntitlementManagement.Read.All` | Application | Access packages, catalogs, policies | **E5 Gov** |
| `AccessReview.Read.All` | Application | Access review definitions and results | **E5 Gov** |
| `LifecycleWorkflows.Read.All` | Application | Lifecycle workflow definitions and runs | **E5 Gov** |
| `SecurityEvents.Read.All` | Application | Secure Score, security alerts, security recommendations | **E5** |

**Note on license requirements:** Permissions marked E5 or E5 Gov will not return data if the tenant does not have the corresponding license. The framework handles this gracefully — those checks will return an `INFO` result rather than an error.

---

## Step 3: Authentication Method

You have two options for authenticating the App Registration. **Certificates are strongly recommended for production use** as they cannot be accidentally logged or exposed in shell history.

### Option A: Client Secret (simpler, suitable for testing)

1. In your App Registration, go to **Certificates & secrets**.
2. Click **New client secret**.
3. Set a description (e.g., `M365Assessment`) and an expiry (maximum 24 months).
4. Click **Add**.
5. **Copy the secret value immediately** — it will not be shown again.

When running the assessment:

```powershell
$secret = ConvertTo-SecureString "your-secret-value" -AsPlainText -Force

.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecret $secret `
    -OutputPath "./reports"
```

Set a calendar reminder to rotate the secret before it expires.

### Option B: Certificate (recommended for production)

1. Generate a self-signed certificate or use your PKI:

```powershell
# Generate a self-signed certificate (valid 2 years)
$cert = New-SelfSignedCertificate `
    -Subject "CN=M365-Security-Assessment" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

Write-Host "Thumbprint: $($cert.Thumbprint)"

# Export the public key (.cer) for upload to Entra
Export-Certificate -Cert $cert -FilePath "M365Assessment.cer"
```

2. In your App Registration, go to **Certificates & secrets > Certificates**.
3. Click **Upload certificate** and upload the `.cer` file.
4. Note the certificate thumbprint.

When running the assessment:

```powershell
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -CertificateThumbprint "your-cert-thumbprint" `
    -OutputPath "./reports"
```

---

## Step 4: Exchange Online Permissions (Optional)

Some email security checks (DMARC, anti-phishing policies, Safe Links, mail flow rules) require Exchange Online PowerShell in addition to Graph API. Use the `-ConnectExchange` switch to enable these checks.

Exchange Online app-only authentication requires:

1. The App Registration must have the **Exchange.ManageAsApp** permission (under **Office 365 Exchange Online**, not Microsoft Graph).
2. The service principal must be assigned the **Exchange Online** management role.

### Assign the Exchange Online role

```powershell
# Connect to Exchange Online as a Global Admin
Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.com

# Add the service principal to the View-Only Organization Management role group
New-ManagementRoleAssignment `
    -App "M365-Security-Assessment" `
    -Role "View-Only Organization Management"

# Verify
Get-ManagementRoleAssignment -App "M365-Security-Assessment"
```

---

## Step 5: Verify the Setup

Test that the App Registration can authenticate and read data before running the full assessment:

```powershell
# Test Graph API connection
Connect-MgGraph `
    -TenantId "your-tenant-id" `
    -ClientId "your-client-id" `
    -ClientSecretCredential (New-Object System.Management.Automation.PSCredential("your-client-id", (ConvertTo-SecureString "your-secret" -AsPlainText -Force)))

# Verify connection
Get-MgContext

# Test a basic read
Get-MgUser -Top 1 -Select DisplayName

Disconnect-MgGraph
```

If the read succeeds without errors, the App Registration is configured correctly.

---

## Security Notes

- The App Registration should be used **exclusively** for this assessment — do not reuse it for other purposes.
- Restrict access to the client secret or certificate private key to the team members who run the assessment.
- Rotate the client secret at least annually, or use a certificate with a defined expiry.
- The App Registration's activity is visible in **Entra ID > Monitoring > Audit logs** and **Sign-in logs** under the service principal name.
- Consider creating a dedicated **administrative unit** or naming convention to make the service principal easily identifiable in audit logs.
