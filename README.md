# SSRS Certificate Auto-Renewal (.NET)

**Beta release** — C# rewrite of the PowerShell SSRS certificate auto-renewal automation.

Designed for environments where PowerShell is blocked or restricted by server hardening (AppLocker, Constrained Language Mode, execution policy, etc.).

## Status

This is an early beta. Core rebinding logic is implemented. Event-driven thumbprint extraction is a placeholder and requires refinement before production use.

## Features

- Processes certificate replace events for SSRS / Power BI Report Server (PBIRS)
- Supports Common Name + Subject Alternative Names (SAN)
- Template name verification (ADSI lookup + local extension fallback)
- Dynamic discovery of SSRS WMI namespaces (SQL Server 2016–2025)
- URL reservation + SSL binding update via `MSReportServer_ConfigurationSetting`
- Duplicate event prevention via state file
- Automatic service restart after successful rebind
- Self-contained single-file publish (no PowerShell or shared runtime required)

## Triggering (PowerShell-free)

Instead of `New-CertificateNotificationTask`, create a regular Task Scheduler task triggered by the Certificate Services Lifecycle event log.

### Event Log

- Log: `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational`
- Event ID: **1001** (certificate replaced / renewed)

### Command-line usage

Manual test / one-off run:

```cmd
SsrsCertRenewal.exe --new <NEW_THUMBPRINT> [--old <OLD_THUMBPRINT>] [--debug]
```

Process the most recent replace event (thumbprint extraction is currently a placeholder):

```cmd
SsrsCertRenewal.exe --from-latest-event [--debug]
```

## Build & Publish

Requires .NET 8 SDK (or later).

```bash
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The self-contained single-file executable is recommended for hardened servers.

## Configuration

Edit the expected template name near the top of `Program.cs` if your environment uses a different template:

```csharp
private const string ExpectedTemplateName = "Web Server ( Auto Renew )";
```

## Known Limitations (Beta)

- `--from-latest-event` currently returns placeholder thumbprints. You must parse the Event XML (or pass thumbprints explicitly) before relying on automatic triggering.
- WMI method parameter order and HRESULT handling should be validated against your specific SSRS version.
- No installer or automatic Task Scheduler registration yet — create the scheduled task manually.

## Origin

C# port of the PowerShell solution in [ssrs_cert-automation](https://github.com/nwlterry/ssrs_cert-automation).
