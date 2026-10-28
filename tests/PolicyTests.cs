using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SsrsCertRenewal;

int failed = 0;
void Check(string name, bool condition)
{
    if (condition) return;
    failed++;
    Console.Error.WriteLine("FAIL " + name);
}

Check("thumbprint accepts 40 hex", CertPolicy.NormalizeThumbprint("aa:bb" + new string('1', 36))?.Length == 40);
Check("thumbprint rejects short", CertPolicy.NormalizeThumbprint("ABCD") == null);
Check("thumbprint rejects injection", CertPolicy.NormalizeThumbprint("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA --setup") == null);
Check("host rejects wildcard", !CertPolicy.IsAcceptableHostName("*.example.com"));
Check("host rejects plus", !CertPolicy.IsAcceptableHostName("+"));
Check("host accepts fqdn", CertPolicy.IsAcceptableHostName("reports.example.com"));
Check("service allowlist", CertPolicy.IsAllowedServiceName("SQLServerReportingServices$INST01"));
Check("service rejects cmd", !CertPolicy.IsAllowedServiceName("cmd.exe"));
Check("wmi rejects slash", !CertPolicy.IsSafeWmiToken("v15\\Admin"));
Check("oid exact", CertPolicy.ExtractTemplateOid("Template=1.3.6.1.4.1.311.21.8.1.2.3") == "1.3.6.1.4.1.311.21.8.1.2.3");
Check("oid missing", CertPolicy.ExtractTemplateOid("not a template") == null);

using var rsa = RSA.Create(2048);
var req = new CertificateRequest("CN=reports.example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
var san = new SubjectAlternativeNameBuilder();
san.AddDnsName("reports.example.com");
san.AddDnsName("+");
san.AddDnsName("*.evil.test");
req.CertificateExtensions.Add(san.Build());
var eku = new OidCollection { new Oid(CertPolicy.ServerAuthEku) };
req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));
using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
var names = CertPolicy.GetDnsNames(cert);
Check("san keeps real host", names.Count == 1 && names[0] == "reports.example.com");
Check("eku server auth", CertPolicy.HasServerAuthEku(cert));
Check("time valid", CertPolicy.IsTimeValid(cert, DateTime.UtcNow));
Check("self-signed chain rejected", !CertPolicy.ChainIsTrusted(cert, out _));

if (failed != 0)
{
    Console.Error.WriteLine(failed + " failed");
    return 1;
}
Console.WriteLine("policy checks passed");
return 0;
