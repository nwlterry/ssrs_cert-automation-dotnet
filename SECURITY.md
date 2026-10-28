# Security review

Reviewed release: `v0.2.0-beta` (commit `d854c48`).
Fixed release: `v0.2.1-beta`.

The program is installed as a Task Scheduler action that runs as `NT AUTHORITY\SYSTEM` and changes the SSRS TLS binding. The review treated every certificate field and every command-line value as untrusted.

## Findings in v0.2.0-beta

| ID | Severity | Issue | Result |
| --- | --- | --- | --- |
| S1 | High | `--setup` could be combined with a thumbprint argument. A crafted Event ID 1001 value such as a thumbprint followed by `--setup` made the SYSTEM task re-register itself. | Fixed. `--setup` is rejected when any certificate argument is present. Task arguments are quoted. Values that are not 40 hex characters are rejected before any WMI call. |
| S2 | High | Task XML was written to a predictable file under the temp directory, which other users can write. | Fixed in v0.2.0 by moving the file, and completed in v0.2.1. The file is created only after `C:\ProgramData\SsrsCertRenewal` is locked to SYSTEM and Administrators. Setup stops if that lock fails. |
| S3 | High | The scheduled task ran whatever file was at the path recorded during setup. A user-writable folder made the next renewal SYSTEM code execution. | Fixed. `--setup` refuses to run when Users, Everyone, or Authenticated Users can write the executable directory. |
| S4 | High | Any certificate whose template text matched was bound on `0.0.0.0:443`, including a renewal of a different site on the same server. The old binding was removed before the new one was created. | Fixed. The new binding is created only when there is no current binding, or the old thumbprint is the one currently bound. The old binding is removed only after the new one succeeds. The new certificate must share a DNS name or subject with the previous certificate when that certificate is still in the store. |
| S5 | Medium | Template check fell back to a substring of the formatted extension when Active Directory could not be contacted. | Fixed. Active Directory lookup is required. A failed lookup rejects the certificate. |
| S6 | Medium | The certificate was accepted without a private key, Server Authentication EKU, validity window, or trusted chain. `validOnly` was false. | Fixed. Private key, EKU `1.3.6.1.5.5.7.3.1`, time, and chain are required. Offline revocation is allowed. A revoked or untrusted chain is not. |
| S7 | Medium | DNS names were scraped from the localized `Format()` text and reserved as-is. `+` or `*` became a wildcard URL reservation. | Fixed. Names come from the SAN extension. `+`, `*`, and non-hostnames are dropped. |
| S8 | Medium | The state file was created with inherited ACLs, so a pre-created directory could suppress later renewals. Event record IDs were stored as 32-bit integers. | Fixed. The state file lives in the locked directory. Record IDs are 64-bit. |
| S9 | Medium | `ServiceName` from WMI was passed to `ServiceController` with a fallback of `SQLServerReportingServices`. | Fixed. Only `SQLServerReportingServices` and `PowerBIReportServer`, with an optional `$instance`, are restarted. |
| S10 | Low | `InitializeReportServer` ran whenever WMI reported the instance was not initialized. | Fixed. An uninitialized instance is left unchanged. |
| S11 | Low | `--debug` printed the raw Event 1001 XML. | Fixed. The raw XML is not written to the console. |
| S12 | Low | `AllowStartOnDemand` was true, and the task ran for up to an hour. | Fixed. On-demand start is disabled. The limit is 10 minutes. |
| S13 | Low | Event XML was parsed without turning off DTD processing. | Fixed. DTDs are prohibited. |
| S14 | Low | WMI namespace names were concatenated into the management path. | Fixed. A namespace token that is not a short identifier is ignored. |

## Residual risk

- The executable must stay in the directory that passed the ACL check. Replacing it later, after an administrator grants Users write access, is still SYSTEM code execution on the next event.
- WMI on the local machine is trusted. A caller who can already replace the SSRS WMI provider can already run as SYSTEM.
- The template allow-list is the display name compiled into `Program.cs` (`Web Server ( Auto Renew )`). A certificate issued from that template, with Server Authentication and a trusted chain, can take an empty SSRS binding. It cannot replace a binding whose thumbprint was not the old certificate.
- `--setup` still does not replay certificates that were replaced before the task existed.
- Online revocation is skipped when the revocation server cannot be reached (`OfflineRevocation`, `RevocationStatusUnknown`). A revoked certificate is rejected when the revocation status is available.
- This review is a source review of the application. It is not a penetration test of the Windows host.

## Checks

`dotnet run --project tests/PolicyTests.csproj -c Release -f net8.0` covers thumbprint shape, hostname rejection, the service-name allow-list, WMI token rejection, template OID parsing, and SAN filtering.
