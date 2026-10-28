using System.Diagnostics;
using System.DirectoryServices;
using System.Management;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SsrsCertRenewal;

class Program
{
    private const string ExpectedTemplateName = "Web Server ( Auto Renew )";
    private const string TaskName = "SSRS-CertRenewal";
    private const int Port = 443;
#if NET10_0_OR_GREATER
    private const string BuiltFor = "net10.0";
#else
    private const string BuiltFor = "net8.0";
#endif

    private static readonly string[] BroadSids = ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"];

    private static bool DebugMode = false;
    private static readonly string ProtectedDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SsrsCertRenewal");
    private static readonly string StateFile = Path.Combine(ProtectedDir, "LastProcessedEventRecordId.txt");

    static async Task<int> Main(string[] args)
    {
        string? newCertHash = null;
        string? oldCertHash = null;
        long? eventRecordId = null;
        bool fromLatestEvent = false;
        bool setup = false;
        bool showVersion = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--new":
                case "-n":
                    if (!TryTake(args, ref i, out newCertHash)) return Usage();
                    break;
                case "--old":
                case "-o":
                    if (!TryTake(args, ref i, out oldCertHash)) return Usage();
                    break;
                case "--event":
                case "-e":
                    if (!TryTake(args, ref i, out var eventText) || !long.TryParse(eventText, out var parsed) || parsed <= 0)
                    {
                        Console.WriteLine("Event record id must be a positive integer.");
                        return 1;
                    }
                    eventRecordId = parsed;
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
                default:
                    Console.WriteLine($"Unknown argument: {args[i]}");
                    return Usage();
            }
        }

        if (showVersion)
        {
            PrintVersion();
            return 0;
        }

        bool renewalRequested = fromLatestEvent || !string.IsNullOrWhiteSpace(newCertHash) || !string.IsNullOrWhiteSpace(oldCertHash);
        if (setup && renewalRequested)
        {
            Console.WriteLine("Refusing to run --setup together with certificate arguments.");
            return 1;
        }

        if (setup)
            return SetupScheduledTask();

        if (fromLatestEvent)
        {
            var latest = GetLatestReplaceEvent();
            if (latest == null)
            {
                Console.WriteLine("No usable certificate replace event found.");
                return 1;
            }
            newCertHash = latest.Value.NewThumbprint;
            oldCertHash = latest.Value.OldThumbprint;
            eventRecordId = latest.Value.RecordId;
            Console.WriteLine($"Processing event {eventRecordId}.");
        }

        newCertHash = CertPolicy.NormalizeThumbprint(newCertHash);
        oldCertHash = string.IsNullOrWhiteSpace(oldCertHash) ? null : CertPolicy.NormalizeThumbprint(oldCertHash);
        if (newCertHash == null)
            return Usage();
        if (oldCertHash == null && !string.IsNullOrWhiteSpace(args.FirstOrDefault(a => a.Equals("--old", StringComparison.OrdinalIgnoreCase) || a.Equals("-o", StringComparison.OrdinalIgnoreCase))))
        {
            Console.WriteLine("Old thumbprint is not 40 hexadecimal characters.");
            return 1;
        }

        try
        {
            return await ProcessCertificateRenewal(newCertHash, oldCertHash, eventRecordId);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR: {ex.Message}");
            if (DebugMode) Console.WriteLine(ex.GetType().Name);
            return 1;
        }
    }

    private static bool TryTake(string[] args, ref int i, out string? value)
    {
        if (i + 1 >= args.Length || args[i + 1].StartsWith('-'))
        {
            value = null;
            Console.WriteLine($"Missing value for {args[i]}.");
            return false;
        }
        value = args[++i];
        return true;
    }

    private static int Usage()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  SsrsCertRenewal.exe --setup");
        Console.WriteLine("  SsrsCertRenewal.exe --new <thumbprint> [--old <thumbprint>] [--event <id>] [--debug]");
        Console.WriteLine("  SsrsCertRenewal.exe --from-latest-event [--debug]");
        Console.WriteLine("  SsrsCertRenewal.exe --version");
        return 1;
    }

    private static int SetupScheduledTask()
    {
        string exePath = Path.GetFullPath(Process.GetCurrentProcess().MainModule?.FileName
            ?? Path.Combine(AppContext.BaseDirectory, "SsrsCertRenewal.exe"));
        string? exeDir = Path.GetDirectoryName(exePath);
        if (exeDir == null || !File.Exists(exePath))
        {
            Console.WriteLine("Could not resolve the executable path.");
            return 1;
        }
        if (DirectoryGrantsWriteToBroadPrincipals(exeDir))
        {
            Console.WriteLine("Refusing --setup. The executable directory is writable by Users, Everyone, or Authenticated Users.");
            Console.WriteLine(exeDir);
            return 1;
        }

        Console.WriteLine($"Registering scheduled task '{TaskName}'.");
        Console.WriteLine($"Executable: {exePath}");

        const string query =
            "<QueryList><Query Id=\"0\" Path=\"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational\">" +
            "<Select Path=\"Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational\">*[System[(EventID=1001)]]</Select>" +
            "</Query></QueryList>";
        string subscription = SecurityElement.Escape(query);
        string command = SecurityElement.Escape(exePath);

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
    <AllowStartOnDemand>false</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>{command}</Command>
      <Arguments>--new ""$(NewCertHash)"" --old ""$(OldCertHash)"" --event ""$(EventRecordId)""</Arguments>
    </Exec>
  </Actions>
</Task>";

        if (!TryLockDownDirectory(ProtectedDir))
            return 1;

        string tempXml = Path.Combine(ProtectedDir, $"task-{Guid.NewGuid():N}.xml");
        File.WriteAllText(tempXml, taskXml, Encoding.Unicode);

        try
        {
            RunProcess("schtasks", $"/Delete /TN \"{TaskName}\" /F");
            var (code, output, error) = RunProcess("schtasks", $"/Create /TN \"{TaskName}\" /XML \"{tempXml}\" /F");
            if (code == 0)
            {
                Console.WriteLine($"Task '{TaskName}' registered. It runs as SYSTEM and cannot be started on demand.");
                Console.WriteLine("Trigger: Event ID 1001. Arguments are quoted thumbprints, not a shell command.");
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
            .FirstOrDefault()?.InformationalVersion ?? "0.2.1-beta";
        Console.WriteLine($"SsrsCertRenewal {informational}");
        Console.WriteLine($"Built for {BuiltFor}. Running on {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}.");
    }

    private static bool TryLockDownDirectory(string dir)
    {
        Directory.CreateDirectory(dir);
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("ACL lockdown is only available on Windows.");
            return false;
        }

        string grant = $"\"{dir}\" /inheritance:r /T /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F";
        var (code, _, error) = RunProcess("icacls", grant);
        if (code != 0)
        {
            RunProcess("takeown", $"/F \"{dir}\" /A");
            (code, _, error) = RunProcess("icacls", grant);
        }
        if (code != 0 || DirectoryGrantsWriteToBroadPrincipals(dir))
        {
            Console.WriteLine("Could not restrict the data directory to SYSTEM and Administrators.");
            if (!string.IsNullOrWhiteSpace(error)) Console.WriteLine(error);
            return false;
        }
        return true;
    }

    private static bool DirectoryGrantsWriteToBroadPrincipals(string directory)
    {
        if (!OperatingSystem.IsWindows()) return false;
        var acl = new DirectoryInfo(directory).GetAccessControl();
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) continue;
            if (!BroadSids.Contains(rule.IdentityReference.Value, StringComparer.OrdinalIgnoreCase)) continue;
            var rights = rule.FileSystemRights;
            if ((rights & (FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.FullControl | FileSystemRights.CreateFiles | FileSystemRights.WriteData)) != 0)
                return true;
        }
        return false;
    }

    private static (int ExitCode, string Output, string Error) RunProcess(string fileName, string arguments)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var proc = Process.Start(psi);
        if (proc == null) return (1, "", $"Failed to start {fileName}.");
        string output = proc.StandardOutput.ReadToEnd();
        string error = proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        return (proc.ExitCode, output, error);
    }

    private static async Task<int> ProcessCertificateRenewal(string newCertHash, string? oldCertHash, long? eventRecordId)
    {
        if (!TryLockDownDirectory(ProtectedDir))
            return 1;

        if (eventRecordId is > 0 && await AlreadyProcessed(eventRecordId.Value))
        {
            Console.WriteLine($"Event {eventRecordId} already processed. Exiting.");
            return 0;
        }

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var newCert = store.Certificates.Find(X509FindType.FindByThumbprint, newCertHash, false).FirstOrDefault();
        if (newCert == null)
        {
            Console.WriteLine("New certificate was not found in LocalMachine\\My.");
            return 1;
        }

        if (!CertPolicy.HasUsablePrivateKey(newCert))
        {
            Console.WriteLine("New certificate has no usable private key. Skipping.");
            return 1;
        }
        if (!CertPolicy.IsTimeValid(newCert, DateTime.UtcNow))
        {
            Console.WriteLine("New certificate is outside its validity period. Skipping.");
            return 1;
        }
        if (!CertPolicy.HasServerAuthEku(newCert))
        {
            Console.WriteLine("New certificate does not have the Server Authentication EKU. Skipping.");
            return 1;
        }
        if (!CertPolicy.ChainIsTrusted(newCert, out string chainError))
        {
            Console.WriteLine($"New certificate chain was rejected: {chainError}");
            return 1;
        }
        if (!VerifyTemplate(newCert))
        {
            Console.WriteLine($"Certificate template does not match '{ExpectedTemplateName}'. Skipping.");
            return 1;
        }

        var dnsNames = CertPolicy.GetDnsNames(newCert);
        if (dnsNames.Count == 0)
        {
            Console.WriteLine("Certificate has no acceptable DNS host name. Skipping.");
            return 1;
        }
        if (DebugMode) Console.WriteLine($"DNS names: {string.Join(", ", dnsNames)}");

        X509Certificate2? oldCert = null;
        if (oldCertHash != null)
        {
            oldCert = store.Certificates.Find(X509FindType.FindByThumbprint, oldCertHash, false).FirstOrDefault();
            if (oldCert != null && !CertPolicy.SharesIdentity(newCert, oldCert))
            {
                Console.WriteLine("New certificate does not share a DNS name or subject with the old certificate. Skipping.");
                return 1;
            }
        }

        var configs = DiscoverSsrsConfigs();
        if (configs.Count == 0)
        {
            Console.WriteLine("No SSRS or PBIRS instances found on this server.");
            return 1;
        }

        int lcid = System.Globalization.CultureInfo.CurrentCulture.LCID;
        bool anySuccess = false;

        foreach (var config in configs)
        {
            Console.WriteLine($"Processing SSRS instance: {config.InstanceName}");
            if (!config.IsInitialized)
            {
                Console.WriteLine("Instance is not initialized. Certificate binding was not changed.");
                continue;
            }

            bool instanceChanged = false;

            foreach (var app in new[] { "ReportServerWebService", "ReportServerWebApp" })
            {
                var current = ListBindingHashes(config.ManagementObject, app, lcid);
                bool hasCurrent = current.Count > 0;
                bool oldIsCurrent = oldCertHash != null && current.Contains(oldCertHash);
                if (hasCurrent && !oldIsCurrent)
                {
                    Console.WriteLine($"  {app}: current binding does not match the old thumbprint. Not changed.");
                    continue;
                }

                foreach (string name in dnsNames)
                {
                    string url = $"https://{name}:{Port}";
                    int reserved = InvokeNamed(config.ManagementObject, "ReserveURL", ("Application", app), ("UrlString", url), ("Lcid", lcid));
                    if (reserved == 0 || reserved == -2147220932)
                        Console.WriteLine($"  ReserveURL {url} -> {reserved}");
                    else
                        Console.WriteLine($"  ReserveURL {url} failed: {reserved}");
                }

                int created = InvokeNamed(
                    config.ManagementObject,
                    "CreateSSLCertificateBinding",
                    ("Application", app),
                    ("CertificateHash", newCertHash.ToLowerInvariant()),
                    ("IPAddress", "0.0.0.0"),
                    ("Port", Port),
                    ("Lcid", lcid));
                Console.WriteLine($"  CreateSSLCertificateBinding -> {created}");
                if (created != 0) continue;

                instanceChanged = true;
                anySuccess = true;
                if (oldIsCurrent && !oldCertHash!.Equals(newCertHash, StringComparison.OrdinalIgnoreCase))
                {
                    int removed = InvokeNamed(
                        config.ManagementObject,
                        "RemoveSSLCertificateBinding",
                        ("Application", app),
                        ("CertificateHash", oldCertHash.ToLowerInvariant()),
                        ("IPAddress", "0.0.0.0"),
                        ("Port", Port),
                        ("Lcid", lcid));
                    Console.WriteLine($"  RemoveSSLCertificateBinding -> {removed}");
                }
            }

            if (instanceChanged)
                RestartIfAllowed(config.ServiceName);
        }

        if (eventRecordId is > 0 && anySuccess)
            await WriteStateAsync(eventRecordId.Value);

        Console.WriteLine(anySuccess
            ? "Certificate rebind completed."
            : "No SSRS binding was changed.");
        return anySuccess ? 0 : 1;
    }

    private static async Task<bool> AlreadyProcessed(long eventRecordId)
    {
        if (!File.Exists(StateFile)) return false;
        string text = await File.ReadAllTextAsync(StateFile);
        return long.TryParse(text.Trim(), out long last) && eventRecordId <= last;
    }

    private static async Task WriteStateAsync(long eventRecordId)
    {
        string tmp = StateFile + ".tmp";
        await File.WriteAllTextAsync(tmp, eventRecordId.ToString());
        if (File.Exists(StateFile)) File.Replace(tmp, StateFile, null);
        else File.Move(tmp, StateFile);
    }

    private static bool VerifyTemplate(X509Certificate2 cert)
    {
        var templateExt = cert.Extensions.OfType<X509Extension>().FirstOrDefault(e => e.Oid?.Value == "1.3.6.1.4.1.311.21.7");
        if (templateExt == null)
        {
            Console.WriteLine("No certificate template extension.");
            return false;
        }

        string? templateOid = CertPolicy.ExtractTemplateOid(templateExt.Format(false));
        if (templateOid == null)
        {
            Console.WriteLine("Could not parse a certificate template OID.");
            return false;
        }

        try
        {
            using var rootDse = new DirectoryEntry("LDAP://RootDSE");
            string? configContext = rootDse.Properties["configurationNamingContext"][0]?.ToString();
            if (string.IsNullOrWhiteSpace(configContext)) return false;
            string searchRoot = $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,{configContext}";

            using var searcher = new DirectorySearcher(new DirectoryEntry(searchRoot))
            {
                Filter = $"(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID={templateOid}))"
            };
            var result = searcher.FindOne();
            if (result == null) return false;

            string adName = result.Properties["name"][0]?.ToString() ?? "";
            string adDisplay = result.Properties["displayname"][0]?.ToString() ?? "";
            bool match = adName.Equals(ExpectedTemplateName, StringComparison.OrdinalIgnoreCase)
                || adDisplay.Equals(ExpectedTemplateName, StringComparison.OrdinalIgnoreCase);
            if (!match)
                Console.WriteLine("Active Directory template name did not match. No local-name fallback is used.");
            return match;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Active Directory template lookup failed. Certificate was not accepted. {ex.Message}");
            return false;
        }
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
                if (!CertPolicy.IsSafeWmiToken(instance)) continue;

                string instancePath = rootNs + "\\" + instance;
                using var verSearcher = new ManagementObjectSearcher("\\\\.\\" + instancePath, "SELECT * FROM __NAMESPACE");
                foreach (ManagementObject versionNs in verSearcher.Get())
                {
                    string version = versionNs["Name"]?.ToString() ?? "";
                    if (!CertPolicy.IsSafeWmiToken(version)) continue;

                    string targetNs = instancePath + "\\" + version + "\\Admin";
                    try
                    {
                        using var configSearcher = new ManagementObjectSearcher("\\\\.\\" + targetNs, "SELECT * FROM MSReportServer_ConfigurationSetting");
                        foreach (ManagementObject mo in configSearcher.Get())
                        {
                            string? serviceName = mo["ServiceName"]?.ToString();
                            results.Add(new SsrsConfig
                            {
                                ManagementObject = mo,
                                InstanceName = mo["InstanceName"]?.ToString() ?? instance,
                                ServiceName = CertPolicy.IsAllowedServiceName(serviceName) ? serviceName : null,
                                IsInitialized = Convert.ToBoolean(mo["IsInitialized"] ?? false)
                            });
                        }
                    }
                    catch
                    {
                        if (DebugMode) Console.WriteLine($"No configuration found in {targetNs}");
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

    private static HashSet<string> ListBindingHashes(ManagementObject mo, string app, int lcid)
    {
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var inParams = mo.GetMethodParameters("ListSSLCertificateBindings");
            SetParam(inParams, "Lcid", lcid);
            var result = mo.InvokeMethod("ListSSLCertificateBindings", inParams, null);
            string[] apps = ReadStrings(result, "Application");
            string[] certs = ReadStrings(result, "CertificateHash");
            int n = Math.Min(apps.Length, certs.Length);
            for (int i = 0; i < n; i++)
            {
                if (!app.Equals(apps[i], StringComparison.OrdinalIgnoreCase)) continue;
                string? hash = CertPolicy.NormalizeThumbprint(certs[i]);
                if (hash != null) hashes.Add(hash);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Could not list current SSL bindings: {ex.Message}");
        }
        return hashes;
    }

    private static int InvokeNamed(ManagementObject mo, string method, params (string Name, object Value)[] args)
    {
        var inParams = mo.GetMethodParameters(method);
        foreach (var (name, value) in args)
        {
            if (!SetParam(inParams, name, value))
                throw new InvalidOperationException($"WMI method {method} has no {name} parameter.");
        }
        var result = mo.InvokeMethod(method, inParams, null);
        return Convert.ToInt32(result["HRESULT"]);
    }

    private static bool SetParam(ManagementBaseObject bag, string name, object value)
    {
        foreach (PropertyData property in bag.Properties)
        {
            if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                bag[property.Name] = value;
                return true;
            }
        }
        if (name.Equals("Lcid", StringComparison.OrdinalIgnoreCase))
            return SetParam(bag, "LCID", value);
        if (name.Equals("UrlString", StringComparison.OrdinalIgnoreCase))
            return SetParam(bag, "Url", value);
        return false;
    }

    private static string[] ReadStrings(ManagementBaseObject result, string name)
    {
        object? value = null;
        foreach (PropertyData property in result.Properties)
        {
            if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                value = property.Value;
                break;
            }
        }
        return value switch
        {
            string[] many => many,
            string one => [one],
            _ => []
        };
    }

    private static void RestartIfAllowed(string? serviceName)
    {
        if (!CertPolicy.IsAllowedServiceName(serviceName))
        {
            Console.WriteLine("Service name is not an SSRS or PBIRS service. Not restarted.");
            return;
        }

        try
        {
            using var sc = new ServiceController(serviceName!);
            if (sc.Status != ServiceControllerStatus.Stopped)
                sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(60));
            Console.WriteLine($"Restarted {serviceName}.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not restart {serviceName}. Restart it manually. {ex.Message}");
        }
    }

    private static (string NewThumbprint, string? OldThumbprint, long RecordId)? GetLatestReplaceEvent()
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

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };
            using var xmlReader = XmlReader.Create(new StringReader(evt.ToXml()), settings);
            var doc = XDocument.Load(xmlReader);
            string? newThumb = CertPolicy.NormalizeThumbprint(FindThumbprint(doc, "NewCertificateDetails"));
            string? oldThumb = CertPolicy.NormalizeThumbprint(FindThumbprint(doc, "OldCertificateDetails"));
            if (newThumb == null)
            {
                Console.WriteLine("Event 1001 did not contain a 40-character new thumbprint.");
                return null;
            }

            long recordId = evt.RecordId ?? 0;
            return (newThumb, oldThumb, recordId);
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
        return element.Attribute("Thumbprint")?.Value
            ?? element.Elements().FirstOrDefault(e => e.Name.LocalName == "Thumbprint")?.Value;
    }

    private sealed class SsrsConfig
    {
        public ManagementObject ManagementObject { get; set; } = null!;
        public string InstanceName { get; set; } = "";
        public string? ServiceName { get; set; }
        public bool IsInitialized { get; set; }
    }
}
