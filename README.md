# SSRS Certificate Auto-Renewal (.NET)

C# rewrite of the PowerShell SSRS certificate auto-renewal automation.

Designed for environments where PowerShell is blocked or restricted by server hardening (AppLocker, Constrained Language Mode, execution policy, etc.).

## Features

- Processes certificate replace events for SSRS / PBIRS
- Supports Common Name + Subject Alternative Names (SAN)
- Template name verification (ADSI + local fallback)
- Dynamic discovery of SSRS WMI namespaces (2016–2025)
- URL reservation + SSL binding update via MSReportServer_ConfigurationSetting
- Duplicate event prevention
- Service restart after successful rebind

## Triggering (PowerShell-free)

Instead of `New-CertificateNotificationTask`, use a regular Task Scheduler task triggered by the Certificate Services Lifecycle event log.

### Event Log

- Log: `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational`
- Event ID: **1001** (certificate replaced / renewed)

### Recommended Task Setup

Create a scheduled task that runs the executable. The tool can read the latest replace event itself.

Example (manual test):

```
SsrsCertRenewal.exe --new <NEW_THUMBPRINT> --old <OLD_THUMBPRINT> --debug
```

Or process the most recent replace event:

```
SsrsCertRenewal.exe --from-latest-event --debug
```

## Build

Requires .NET 8 SDK (or later).

```bash
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

The self-contained single-file publish is recommended for hardened servers (no dependency on PowerShell or a shared .NET runtime).

## Configuration

Edit the expected template name near the top of `Program.cs` if needed:

```csharp
private const string ExpectedTemplateName = "Web Server ( Auto Renew )";
```

## Origin

C# port of the PowerShell solution in [ssrs_cert-automation](https://github.com/nwlterry/ssrs_cert-automation).
