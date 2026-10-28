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
- **`--setup` mode** registers the scheduled task (replaces the PowerShell Deploy script)
- Self-contained single-file publish (no PowerShell or shared runtime required)

## Execution

### Setup (register scheduled task)

Run once (as Administrator) to create the event-triggered task:

```cmd
SsrsCertRenewal.exe --setup
```

This creates task `SSRS-CertRenewal` that triggers on Event ID 1001 and runs the executable with `--from-latest-event`.

### Manual / one-off run

```cmd
SsrsCertRenewal.exe --new <NEW_THUMBPRINT> [--old <OLD_THUMBPRINT>] [--debug]
```

### Process latest replace event

```cmd
SsrsCertRenewal.exe --from-latest-event [--debug]
```

> Note: thumbprint extraction from the event is currently a placeholder. Prefer explicit `--new` / `--old` until this is refined.

## Scheduled Task Setup (PowerShell-free)

The preferred method is:

```cmd
SsrsCertRenewal.exe --setup
```

This registers a task with:
- Trigger: Event ID **1001** in `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational`
- Action: runs this executable with `--from-latest-event`
- Principal: SYSTEM (highest available)

### Manual alternative

If you prefer to create the task yourself, use the Task Scheduler GUI or export an XML and import it. The event trigger details are the same as above.

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
- `--setup` creates the task but the event parser still needs real thumbprint extraction for fully automatic operation.

## Origin

C# port of the PowerShell solution in [ssrs_cert-automation](https://github.com/nwlterry/ssrs_cert-automation).
