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

## Execution

### Manual / one-off run

```cmd
SsrsCertRenewal.exe --new <NEW_THUMBPRINT> [--old <OLD_THUMBPRINT>] [--debug]
```

Example:

```cmd
SsrsCertRenewal.exe --new A1B2C3D4E5F6... --old 9F8E7D6C5B4A... --debug
```

### Process latest replace event

```cmd
SsrsCertRenewal.exe --from-latest-event [--debug]
```

> Note: thumbprint extraction from the event is currently a placeholder. Prefer explicit `--new` / `--old` until this is refined.

## Scheduled Task Setup (PowerShell-free)

Create a Task Scheduler task that triggers on the certificate replace event and runs the executable.

### Event trigger

- **Log**: `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational`
- **Event ID**: `1001` (certificate replaced / renewed)

### Recommended task configuration

1. Run as `SYSTEM` (or an account with rights to the certificate store, WMI, and the SSRS service).
2. Action: Start a program
   - Program: full path to `SsrsCertRenewal.exe`
   - Arguments (example using explicit thumbprints once you can extract them, or use `--from-latest-event`):
     ```
     --from-latest-event --debug
     ```
   - Start in: directory containing the executable
3. Configure for: Windows Server 2016 or later
4. Enable "Run whether user is logged on or not"

### Example schtasks command (basic)

```cmd
schtasks /Create /TN "SSRS-CertRenewal" /TR "C:\Tools\SsrsCertRenewal.exe --from-latest-event" /SC ONCE /ST 00:00 /F
```

For a proper event-based trigger, create the task via Task Scheduler GUI (or export/import an XML definition) and set the trigger to the Event Log entry above. The `schtasks` CLI has limited support for complex event triggers.

### Event XML notes

Event ID 1001 in the Lifecycle-System log contains the old and new certificate thumbprints. Once the `--from-latest-event` parser is completed, the task can simply invoke:

```cmd
SsrsCertRenewal.exe --from-latest-event
```

Until then, you can use a small wrapper or pass the thumbprints explicitly if you extract them another way.

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
- No automatic Task Scheduler registration yet — create the scheduled task manually (see above).

## Origin

C# port of the PowerShell solution in [ssrs_cert-automation](https://github.com/nwlterry/ssrs_cert-automation).
