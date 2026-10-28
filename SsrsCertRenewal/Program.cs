using System.DirectoryServices;
using System.Management;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Xml.Linq;

namespace SsrsCertRenewal;

class Program
{
    // =====================================================================
    // CONFIGURATION
    // =====================================================================
    private const string ExpectedTemplateName = "Web Server ( Auto Renew )";
    private const string TaskName = "SSRS-CertRenewal";
#if NET10_0_OR_GREATER
    private const string BuiltFor = "net10.0";
#else
    private const string BuiltFor = "net8.0";
#endif
    // =====================================================================

    private static bool DebugMode = false;
    private static readonly string StatePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "CertificateNotificationTasks");
    private static readonly string StateFile = Path.Combine(StatePath, "LastProcessedEventRecordId.txt");

    static async Task<int> Main(string[] args)
    {
        string? newCertHash = null;
        string? oldCertHash = null;
        int? eventRecordId = null;
        bool fromLatestEvent = false;
        bool setup = false;
        bool showVersion = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--new":
                case "-n":
                    newCertHash = args[++i];
                    break;
                case "--old":
                case "-o":
                    oldCertHash = args[++i];
                    break;
                case "--event":
                case "-e":
                    if (int.TryParse(args[++i], out var parsedEventId))
                        eventRecordId = parsedEventId;
                    break;
                case "--debug":
                case "-d":
                    DebugMode = true;
                    break;
                case "--from-latest-event":
                    fromLatestEvent = true;
                    break;
                case "--setup":
                    setup = true;
                    break;
                case "--version":
                case "-v":
                    showVersion = true;
                    break;
            }
        }

        if (showVersion)
        {
            PrintVersion();
            return 0;
        }

        if (setup)
        {
            return SetupScheduledTask();
        }

        if (fromLatestEvent)
        {
            var latest = GetLatestReplaceEvent();
            if (latest == null)
            {
                Console.WriteLine("No recent certificate replace event found.");
                return 1;
            }
            newCertHash = latest.Value.NewThumbprint;
            oldCertHash = latest.Value.OldThumbprint;
            eventRecordId = latest.Value.RecordId;
            Console.WriteLine($"Processing latest event {eventRecordId}: New={newCertHash}, Old={oldCertHash}");
        }

        if (string.IsNullOrWhiteSpace(newCertHash))
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  SsrsCertRenewal.exe --setup                  Register scheduled task");
            Console.WriteLine("  SsrsCertRenewal.exe --new <thumbprint> [--old <thumbprint>] [--debug]");
            Console.WriteLine("  SsrsCertRenewal.exe --from-latest-event [--debug]");
            Console.WriteLine("  SsrsCertRenewal.exe --version");
            return 1;
        }

        try
        {
            await ProcessCertificateRenewal(newCertHash.ToUpperInvariant(), oldCertHash?.ToUpperInvariant(), eventRecordId);
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: {ex.Message}");
            if (DebugMode) Console.WriteLine(ex);
            return 1;
        }
    }

    /// <summary>
    /// Registers a Task Scheduler task triggered by CertificateServicesClient Event ID 1001.
    /// ValueQueries pass the old/new thumbprints the same way IIS AutoCertRebind does,
    /// which is the non-PowerShell equivalent of New-CertificateNotificationTask -Type Replace.
    /// </summary>
    private static int SetupScheduledTask()
    {
        string exePath = Process.GetCurrentProcess().MainModule?.FileName
            ?? Path.Combine(AppContext.BaseDirectory, "SsrsCertRenewal.exe");

        Console.WriteLine($"Registering scheduled task '{TaskName}'...");
        Console.WriteLine($"Executable: {exePath}");

        const string query =
            "<QueryList><Query Id=\"0\" Path=\"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational\">" +
            "<Select Path=\"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational\">*[System[(EventID=1001)]]</Select>" +
            "</Query></QueryList>";
        string subscription = SecurityElement.Escape(query);

        string taskXml = $@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.4"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <RegistrationInfo>
    <Description>SSRS certificate auto-renewal. Fires on CertificateServicesClient replace (Event ID 1001) and rebinds SSRS.</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>{subscription}</Subscription>
      <ValueQueries>
        <Value name=""NewCertHash"">Event/UserData/CertNotificationData/NewCertificateDetails/@Thumbprint</Value>
        <Value name=""OldCertHash"">Event/UserData/CertNotificationData/OldCertificateDetails/@Thumbprint</Value>
        <Value name=""EventRecordId"">Event/System/EventRecordID</Value>
      </ValueQueries>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id=""Author"">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>{SecurityElement.Escape(exePath)}</Command>
      <Arguments>--new $(NewCertHash) --old $(OldCertHash) --event $(EventRecordId)</Arguments>
    </Exec>
  </Actions>
</Task>";

        string tempXml = CreateTaskXmlPath();
        File.WriteAllText(tempXml, taskXml, Encoding.Unicode);

        try
        {
            RunSchtasks($"/Delete /TN \"{TaskName}\" /F");

            var (code, output, error) = RunSchtasks($"/Create /TN \"{TaskName}\" /XML \"{tempXml}\" /F");
            if (code == 0)
            {
                Console.WriteLine($"Task '{TaskName}' registered successfully.");
                Console.WriteLine("Trigger: Event ID 1001 (certificate replace) with OldCertHash / NewCertHash from the event.");
                Console.WriteLine($"Action: \"{exePath}\" --new $(NewCertHash) --old $(OldCertHash) --event $(EventRecordId)");
                Console.WriteLine("Runs as NT AUTHORITY\\SYSTEM.");
                return 0;
            }

            Console.WriteLine($"Failed to create task. Exit code: {code}");
            if (!string.IsNullOrWhiteSpace(output)) Console.WriteLine(output);
            if (!string.IsNullOrWhiteSpace(error)) Console.WriteLine(error);
            return 1;
        }
        finally
        {
            try { File.Delete(tempXml); } catch { }
        }
    }

    private static void PrintVersion()
    {
        string informational = typeof(Program).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?.InformationalVersion ?? "0.2.0-beta";
        Console.WriteLine($"SsrsCertRenewal {informational}");
        Console.WriteLine($"Built for {BuiltFor}. Running on {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}.");
        Console.WriteLine("Framework-dependent net8.0 builds roll forward to .NET 10 when .NET 8 is not installed.");
    }

    /// <summary>
    /// Task XML must not be written to the user-writable temp directory.
    /// schtasks reads it as SYSTEM during --setup.
    /// </summary>
    private static string CreateTaskXmlPath()
    {
        string dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SsrsCertRenewal");
        Directory.CreateDirectory(dir);
        try
        {
            var psi = new ProcessStartInfo(
                "icacls",
                $"\"{dir}\" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(10000);
        }
        catch
        {
            // icacls exists only on Windows. The directory is still under ProgramData, not Temp.
        }

        return Path.Combine(dir, $"task-{Guid.NewGuid():N}.xml");
    }

    private static (int ExitCode, string Output, string Error) RunSchtasks(string arguments)
    {
        var psi = new ProcessStartInfo("schtasks", arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc == null) return (1, "", "Failed to start schtasks.");
        string output = proc.StandardOutput.ReadToEnd();
        string error = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (proc.ExitCode, output, error);
    }

    private static async Task ProcessCertificateRenewal(string newCertHash, string? oldCertHash, int? eventRecordId)
    {
        if (DebugMode) Console.WriteLine("=== DEBUG MODE ENABLED ===");

        // 1. Duplicate Execution Prevention
        if (eventRecordId.HasValue)
        {
            Directory.CreateDirectory(StatePath);
            int lastId = 0;
            if (File.Exists(StateFile))
            {
                int.TryParse(await File.ReadAllTextAsync(StateFile), out lastId);
            }
            if (eventRecordId.Value <= lastId)
            {
                Console.WriteLine($"Event {eventRecordId} already processed. Exiting.");
                return;
            }
        }

        // Load certificate
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var newCert = store.Certificates.Find(X509FindType.FindByThumbprint, newCertHash, false).FirstOrDefault();
        if (newCert == null)
            throw new Exception($"New certificate {newCertHash} not found in LocalMachine\\My store.");

        if (DebugMode) Console.WriteLine($"New Cert Subject : {newCert.Subject}");

        // 2. Extract DNS Names (SAN + CN)
        var dnsNames = ExtractDnsNames(newCert);
        if (DebugMode) Console.WriteLine($"DNS Names: {string.Join(", ", dnsNames)}");

        // 3. Verify Certificate Template Match
        if (!string.IsNullOrEmpty(ExpectedTemplateName) && !VerifyTemplate(newCert))
        {
            Console.WriteLine($"Certificate template does not match expected name: '{ExpectedTemplateName}'. Skipping.");
            if (eventRecordId.HasValue) await File.WriteAllTextAsync(StateFile, eventRecordId.Value.ToString());
            return;
        }

        // 4. Discover SSRS instances
        var configs = DiscoverSsrsConfigs();
        if (configs.Count == 0)
        {
            Console.WriteLine("No SSRS or PBIRS instances found on this server.");
            return;
        }

        const int port = 443;
        int lcid = System.Globalization.CultureInfo.CurrentCulture.LCID;

        bool anySuccess = false;

        foreach (var config in configs)
        {
            Console.WriteLine($"\n=== Processing SSRS Instance: {config.InstanceName} ===");
            if (DebugMode)
            {
                Console.WriteLine($" IsInitialized : {config.IsInitialized}");
                Console.WriteLine($" ServiceName   : {config.ServiceName}");
            }

            bool instanceSuccess = false;

            foreach (var app in new[] { "ReportServerWebService", "ReportServerWebApp" })
            {
                Console.WriteLine($"-> Application: {app}");

                foreach (var name in dnsNames)
                {
                    var url = $"https://{name}:{port}";
                    try
                    {
                        var result = InvokeMethod(config.ManagementObject, "ReserveURL", new object[] { app, url, lcid });
                        int hresult = Convert.ToInt32(result["HRESULT"]);
                        if (hresult == 0)
                        {
                            Console.WriteLine($"   ReserveURL {url} → Success (0)");
                            instanceSuccess = true;
                        }
                        else if (hresult == -2147220932)
                        {
                            Console.WriteLine($"   ReserveURL {url} → Already Reserved (OK)");
                            instanceSuccess = true;
                        }
                        else
                        {
                            Console.WriteLine($"   ReserveURL {url} → HRESULT: {hresult}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"   ReserveURL failed for {url} : {ex.Message}");
                    }
                }

                if (!string.IsNullOrEmpty(oldCertHash))
                {
                    try
                    {
                        var result = InvokeMethod(config.ManagementObject, "RemoveSSLCertificateBinding",
                            new object[] { app, oldCertHash.ToLowerInvariant(), "0.0.0.0", port, lcid });
                        Console.WriteLine($"   RemoveSSLCertificateBinding (Old Cert) → HRESULT: {result["HRESULT"]}");
                    }
                    catch
                    {
                        Console.WriteLine("   RemoveSSLCertificateBinding: No old binding found or removal failed.");
                    }
                }

                try
                {
                    var result = InvokeMethod(config.ManagementObject, "CreateSSLCertificateBinding",
                        new object[] { app, newCertHash.ToLowerInvariant(), "0.0.0.0", port, lcid });
                    int hresult = Convert.ToInt32(result["HRESULT"]);
                    Console.WriteLine($"   CreateSSLCertificateBinding (New Cert) → HRESULT: {hresult}");
                    if (hresult == 0) instanceSuccess = true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"   CreateSSLCertificateBinding failed: {ex.Message}");
                }
            }

            if (!config.IsInitialized)
            {
                try
                {
                    Console.WriteLine("Initializing Report Server...");
                    InvokeMethod(config.ManagementObject, "InitializeReportServer", new object[] { config.InstallationID });
                    Console.WriteLine("✓ Initialization completed.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to initialize server: {ex.Message}");
                }
            }

            if (instanceSuccess)
            {
                anySuccess = true;
                string serviceName = config.ServiceName ?? "SQLServerReportingServices";
                Console.WriteLine($"Restarting '{serviceName}' service to apply bindings...");
                try
                {
                    using var sc = new ServiceController(serviceName);
                    if (sc.Status != ServiceControllerStatus.Stopped)
                        sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
                    Console.WriteLine("✓ Service restarted successfully.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to restart service '{serviceName}'. You may need to restart it manually. Error: {ex.Message}");
                }
            }
        }

        if (eventRecordId.HasValue && anySuccess)
            await File.WriteAllTextAsync(StateFile, eventRecordId.Value.ToString());

        Console.WriteLine("\nUniversal SSRS certificate auto-renewal and rebind processing completed.");
    }

    private static List<string> ExtractDnsNames(X509Certificate2 cert)
    {
        var names = new List<string>();

        var sanExt = cert.Extensions.OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        if (sanExt != null)
        {
            var formatted = sanExt.Format(true);
            foreach (var line in formatted.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
                    names.Add(line.Substring("DNS Name=".Length).Trim());
            }
        }

        if (names.Count == 0 && cert.Subject.Contains("CN="))
        {
            var match = Regex.Match(cert.Subject, @"CN=([^,]+)");
            if (match.Success)
                names.Add(match.Groups[1].Value.Trim());
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool VerifyTemplate(X509Certificate2 cert)
    {
        Console.WriteLine($"Template verification active. Expecting: '{ExpectedTemplateName}'");

        var templateExt = cert.Extensions.OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "1.3.6.1.4.1.311.21.7");

        if (templateExt == null)
        {
            Console.WriteLine("No Template Information OID found on certificate. Skipping.");
            return false;
        }

        var formatted = templateExt.Format(false);
        var oidMatch = Regex.Match(formatted, @"1\.3\.6\.1\.4\.1\.311\.21\.8\.[0-9.]+");
        if (!oidMatch.Success)
        {
            Console.WriteLine("Could not parse Template OID string from certificate extension. Skipping.");
            return false;
        }

        string templateOid = oidMatch.Value;
        if (DebugMode) Console.WriteLine($"Extracted Template OID from Cert: {templateOid}");

        try
        {
            using var rootDse = new DirectoryEntry("LDAP://RootDSE");
            string configContext = rootDse.Properties["configurationNamingContext"][0].ToString()!;
            string searchRoot = $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configContext}";

            using var searcher = new DirectorySearcher(new DirectoryEntry(searchRoot))
            {
                Filter = $"(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID={templateOid}))"
            };

            var result = searcher.FindOne();
            if (result != null)
            {
                string adName = result.Properties["name"][0]?.ToString() ?? "";
                string adDisplay = result.Properties["displayname"][0]?.ToString() ?? "";
                if (DebugMode) Console.WriteLine($"Resolved OID in AD to Template: {adName} / {adDisplay}");

                if (adName.Equals(ExpectedTemplateName, StringComparison.OrdinalIgnoreCase) ||
                    adDisplay.Equals(ExpectedTemplateName, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"✓ Certificate verified. Matches template: {ExpectedTemplateName}");
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            if (DebugMode) Console.WriteLine($"ADSI Lookup failed, falling back to local string match. ({ex.Message})");
        }

        if (formatted.Contains(ExpectedTemplateName, StringComparison.OrdinalIgnoreCase))
        {
            if (DebugMode) Console.WriteLine("Matched template name via local extension fallback.");
            Console.WriteLine($"✓ Certificate verified. Matches template: {ExpectedTemplateName}");
            return true;
        }

        return false;
    }

    private static List<SsrsConfig> DiscoverSsrsConfigs()
    {
        var results = new List<SsrsConfig>();
        const string rootNs = @"root\Microsoft\SqlServer\ReportServer";

        try
        {
            using var searcher = new ManagementObjectSearcher("\\\\.\\" + rootNs, "SELECT * FROM __NAMESPACE");
            foreach (ManagementObject instanceNs in searcher.Get())
            {
                string instance = instanceNs["Name"]?.ToString() ?? "";
                if (string.IsNullOrEmpty(instance)) continue;

                string instancePath = $"{rootNs}\\{instance}";
                using var verSearcher = new ManagementObjectSearcher("\\\\.\\" + instancePath, "SELECT * FROM __NAMESPACE");
                foreach (ManagementObject versionNs in verSearcher.Get())
                {
                    string version = versionNs["Name"]?.ToString() ?? "";
                    if (string.IsNullOrEmpty(version)) continue;

                    string targetNs = $"{instancePath}\\{version}\\Admin";
                    try
                    {
                        using var configSearcher = new ManagementObjectSearcher("\\\\.\\" + targetNs, "SELECT * FROM MSReportServer_ConfigurationSetting");
                        foreach (ManagementObject mo in configSearcher.Get())
                        {
                            results.Add(new SsrsConfig
                            {
                                ManagementObject = mo,
                                InstanceName = mo["InstanceName"]?.ToString() ?? instance,
                                ServiceName = mo["ServiceName"]?.ToString(),
                                IsInitialized = Convert.ToBoolean(mo["IsInitialized"] ?? false),
                                InstallationID = mo["InstallationID"]?.ToString()
                            });
                            if (DebugMode) Console.WriteLine($"Discovered SSRS Namespace: {targetNs}");
                        }
                    }
                    catch
                    {
                        if (DebugMode) Console.WriteLine($"No ConfigurationSetting found in {targetNs}");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            if (DebugMode) Console.WriteLine($"WMI discovery error: {ex.Message}");
        }

        return results;
    }

    private static ManagementBaseObject InvokeMethod(ManagementObject mo, string methodName, object[] args)
    {
        var inParams = mo.GetMethodParameters(methodName);
        var paramNames = inParams.Properties.Cast<PropertyData>().Select(p => p.Name).ToArray();

        for (int i = 0; i < args.Length && i < paramNames.Length; i++)
            inParams[paramNames[i]] = args[i];

        return mo.InvokeMethod(methodName, inParams, null);
    }

    private static (string NewThumbprint, string? OldThumbprint, int RecordId)? GetLatestReplaceEvent()
    {
        try
        {
            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational",
                System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[(EventID=1001)]]")
            {
                ReverseDirection = true
            };

            using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
            var evt = reader.ReadEvent();
            if (evt == null) return null;

            string xml = evt.ToXml();
            if (DebugMode) Console.WriteLine(xml);

            var doc = XDocument.Parse(xml);
            string? newThumb = FindThumbprint(doc, "NewCertificateDetails");
            string? oldThumb = FindThumbprint(doc, "OldCertificateDetails");
            if (string.IsNullOrWhiteSpace(newThumb))
            {
                Console.WriteLine("Event 1001 was found but NewCertificateDetails/@Thumbprint was missing.");
                return null;
            }

            int recordId = evt.RecordId.HasValue ? (int)evt.RecordId.Value : 0;
            return (newThumb, string.IsNullOrWhiteSpace(oldThumb) ? null : oldThumb, recordId);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to read certificate replace event: {ex.Message}");
            return null;
        }
    }

    private static string? FindThumbprint(XDocument doc, string elementLocalName)
    {
        var element = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == elementLocalName);
        if (element == null) return null;

        string? value = element.Attribute("Thumbprint")?.Value
            ?? element.Elements().FirstOrDefault(e => e.Name.LocalName == "Thumbprint")?.Value;
        if (string.IsNullOrWhiteSpace(value)) return null;

        value = value.Replace(" ", "", StringComparison.Ordinal).Trim();
        return value.Length == 0 ? null : value;
    }

    private class SsrsConfig
    {
        public ManagementObject ManagementObject { get; set; } = null!;
        public string InstanceName { get; set; } = "";
        public string? ServiceName { get; set; }
        public bool IsInitialized { get; set; }
        public string? InstallationID { get; set; }
    }
}
