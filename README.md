# m365-security-assessment

## 🇩🇪 Beschreibung

**M365 Security Assessment Framework** — Ein PowerShell-basiertes Tool zur automatisierten Sicherheitsüberprüfung von Microsoft 365 Tenants über die **Microsoft Graph API** (read-only).

Das Framework prüft fünf Sicherheitsbereiche und generiert einen detaillierten Bericht mit Handlungsempfehlungen.

### Was wird geprüft?

| Bereich | Was wird analysiert? |
|---|---|
| 🔐 **Identity** | MFA-Status, Conditional Access Policies, privilegierte Rollen, Guest-Accounts |
| 📧 **Email Security** | DMARC/DKIM/SPF, Anti-Phishing Policies, Safe Links, Safe Attachments |
| 💻 **Endpoint** | Intune Compliance Policies, Device Enrollment, Defender Status |
| 📁 **Data Protection** | Sensitivity Labels, DLP Policies, Information Protection |
| 📊 **Monitoring** | Audit Log, Alert Policies, Risky Users, SIEM Integration |

### Output

- 📄 **HTML Report**: Interaktiver Browser-Viewer mit Ampelsystem
- 📝 **Word Report**: Formatierter Bericht für Management-Präsentationen
- 🔧 **JSON Export**: Maschinenlesbare Daten für weitere Verarbeitung

---

## 🇬🇧 Description

**M365 Security Assessment Framework** — A PowerShell-based tool for automated security assessment of Microsoft 365 tenants via the **Microsoft Graph API** (read-only).

The framework checks five security areas and generates a detailed report with recommendations.

---

## 🔑 Required Permissions / Benötigte Berechtigungen

```powershell
# Microsoft Graph API — Read-Only Permissions (Application or Delegated)
Policy.Read.All                    # Conditional Access Policies
Directory.Read.All                 # Users, Groups, Roles
Reports.Read.All                   # Usage Reports
SecurityEvents.Read.All            # Security Alerts
MailboxSettings.Read               # Mailbox Configuration
DeviceManagementConfiguration.Read.All  # Intune Policies
InformationProtectionPolicy.Read.All    # Sensitivity Labels
AuditLog.Read.All                  # Audit Logs
```

### App Registration Setup

```powershell
# App Registration in Entra ID erstellen
# Azure Portal → Entra ID → App Registrations → New Registration
# API Permissions → Add Permissions → Microsoft Graph → Application

# Nach Erstellung: Client ID, Tenant ID und Secret in assessment-config.json eintragen
```

---

## 🚀 Usage / Verwendung

```powershell
# 1. Repository klonen
git clone https://github.com/yusufxsert/m365-security-assessment.git
cd m365-security-assessment

# 2. Abhängigkeiten installieren
Install-Module Microsoft.Graph -Scope CurrentUser

# 3. Assessment starten
.\scripts\Start-M365Assessment.ps1 `
    -TenantId "your-tenant-id" `
    -ClientId "your-app-registration-id" `
    -ClientSecret "your-client-secret" `
    -OutputPath ".\reports"

# 4. Report öffnen
Start-Process ".\reports\M365Assessment_$(Get-Date -Format 'yyyy-MM-dd').html"
```

---

## 🛠️ Technologien / Technologies

![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=flat&logo=powershell&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph%20API-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Microsoft 365](https://img.shields.io/badge/Microsoft%20365-D83B01?style=flat&logo=microsoftoffice&logoColor=white)

**Autor / Author:** Yusuf Sert
