# SSRS Certificate Auto-Renewal (.NET)

**Beta release** — C# rewrite of the PowerShell SSRS certificate auto-renewal automation.

Designed for environments where PowerShell is blocked or restricted by server hardening (AppLocker, Constrained Language Mode, execution policy, etc.).

## Status

This is a beta. The rebind path and the scheduled-task registration path are both in the executable. `--setup` is the replacement for `Deploy-CertificateRenewalTasks.ps1`. It does not call `New-CertificateNotificationTask` (that cmdlet only launches a PowerShell script).

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

This creates task `SSRS-CertRenewal` (runs as SYSTEM). On Event ID 1001 it passes the thumbprints from the event, the same fields IIS AutoCertRebind uses:

```cmd
SsrsCertRenewal.exe --new $(NewCertHash) --old $(OldCertHash) --event $(EventRecordId)
```

### Manual / one-off run

```cmd
SsrsCertRenewal.exe --new <NEW_THUMBPRINT> [--old <OLD_THUMBPRINT>] [--debug]
```

### Process latest replace event

```cmd
SsrsCertRenewal.exe --from-latest-event [--debug]
```

This reads the newest Event ID 1001 and takes `NewCertificateDetails/@Thumbprint` and `OldCertificateDetails/@Thumbprint`.

## What the executable covers

| Original PowerShell | .NET |
| --- | --- |
| `Deploy-CertificateRenewalTasks.ps1` registers a Replace notification task | `SsrsCertRenewal.exe --setup` registers the Task Scheduler event trigger |
| Task passes `OldCertHash`, `NewCertHash`, `EventRecordId` | Same three values, via event ValueQueries |
| `Update-RenewedSystemCertificates_V5.ps1` rebinds SSRS (CN + SAN, template check, WMI, service restart) | Same flow inside the executable |
| `New-CertificateNotificationTask -RunTaskForExistingCertificates` replays already-renewed certs once at deploy time | Not covered. Run once manually with `--new` / `--old` if a cert was already replaced before the task existed |
| Deploy only if an "Internal Web Server" cert is in the store | Not a deploy gate. The runtime filter is the template name in `Program.cs` (`Web Server ( Auto Renew )`) |

## Scheduled Task Setup (PowerShell-free)

The preferred method is:

```cmd
SsrsCertRenewal.exe --setup
```

This registers a task with:
- Trigger: Event ID **1001** in `Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational`
- Value queries: `NewCertificateDetails/@Thumbprint`, `OldCertificateDetails/@Thumbprint`, `EventRecordID`
- Action: `SsrsCertRenewal.exe --new $(NewCertHash) --old $(OldCertHash) --event $(EventRecordId)`
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

- WMI method parameter order and HRESULT handling should be validated against your specific SSRS version.
- `--setup` does not replay already-replaced certificates (`-RunTaskForExistingCertificates` is not implemented).
- Template expected at runtime is `Web Server ( Auto Renew )`, not the deploy script's `Internal Web Server` name check.

## Origin

C# port of the PowerShell solution in [ssrs_cert-automation](https://github.com/nwlterry/ssrs_cert-automation).
