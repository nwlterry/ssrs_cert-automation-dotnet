using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace SsrsCertRenewal;

/// <summary>
/// Pure checks used before the process, running as SYSTEM, changes SSRS bindings.
/// </summary>
public static class CertPolicy
{
    public const string ServerAuthEku = "1.3.6.1.5.5.7.3.1";

    private static readonly Regex ThumbprintRegex = new("^[0-9A-Fa-f]{40}$", RegexOptions.CultureInvariant);
    private static readonly Regex TemplateOidRegex = new(@"1\.3\.6\.1\.4\.1\.311\.21\.8(?:\.\d+)+", RegexOptions.CultureInvariant);
    private static readonly Regex HostnameRegex = new(
        @"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$",
        RegexOptions.CultureInvariant);
    private static readonly Regex ServiceNameRegex = new(
        @"^(SQLServerReportingServices|PowerBIReportServer)(\$[A-Za-z][A-Za-z0-9_]{0,15})?$",
        RegexOptions.CultureInvariant);
    private static readonly Regex WmiNameRegex = new(@"^[A-Za-z][A-Za-z0-9_.-]{0,63}$", RegexOptions.CultureInvariant);

    public static string? NormalizeThumbprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        string compact = value.Replace(" ", "", StringComparison.Ordinal).Replace(":", "", StringComparison.Ordinal).Trim();
        return ThumbprintRegex.IsMatch(compact) ? compact.ToUpperInvariant() : null;
    }

    public static string? ExtractTemplateOid(string formattedExtension)
    {
        if (string.IsNullOrEmpty(formattedExtension)) return null;
        var match = TemplateOidRegex.Match(formattedExtension);
        if (!match.Success) return null;
        int end = match.Index + match.Length;
        if (end < formattedExtension.Length && char.IsDigit(formattedExtension[end])) return null;
        return match.Value;
    }

    public static bool IsAcceptableHostName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        string host = name.Trim().TrimEnd('.');
        if (host.Contains('*') || host.Contains('+') || host.Contains('/') || host.Contains('\\') || host.Contains(':'))
            return false;
        return HostnameRegex.IsMatch(host);
    }

    public static bool IsAllowedServiceName(string? serviceName) =>
        !string.IsNullOrWhiteSpace(serviceName) && ServiceNameRegex.IsMatch(serviceName);

    public static bool IsSafeWmiToken(string? token) =>
        !string.IsNullOrWhiteSpace(token) && WmiNameRegex.IsMatch(token);

    public static List<string> GetDnsNames(X509Certificate2 cert)
    {
        var names = new List<string>();
        var sanExt = cert.Extensions.OfType<X509Extension>().FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
        if (sanExt != null)
        {
            try
            {
                var parsed = new X509SubjectAlternativeNameExtension(sanExt.RawData, sanExt.Critical);
                foreach (string dns in parsed.EnumerateDnsNames())
                {
                    if (IsAcceptableHostName(dns))
                        names.Add(dns.Trim().TrimEnd('.'));
                }
            }
            catch (CryptographicException)
            {
                // Fail closed: do not scrape the localized Format() text.
            }
        }

        if (names.Count == 0)
        {
            string cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            if (IsAcceptableHostName(cn))
                names.Add(cn.Trim().TrimEnd('.'));
        }

        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static bool HasServerAuthEku(X509Certificate2 cert)
    {
        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku == null) return false;
        foreach (Oid oid in eku.EnhancedKeyUsages)
        {
            if (oid.Value == ServerAuthEku) return true;
        }
        return false;
    }

    public static bool HasUsablePrivateKey(X509Certificate2 cert)
    {
        if (!cert.HasPrivateKey) return false;
        try
        {
            using var rsa = cert.GetRSAPrivateKey();
            using var ecdsa = cert.GetECDsaPrivateKey();
            return rsa != null || ecdsa != null;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static bool IsTimeValid(X509Certificate2 cert, DateTime utcNow)
    {
        DateTime notBefore = cert.NotBefore.ToUniversalTime().AddMinutes(-5);
        DateTime notAfter = cert.NotAfter.ToUniversalTime();
        return utcNow >= notBefore && utcNow <= notAfter;
    }

    public static bool ChainIsTrusted(X509Certificate2 cert, out string error)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = DateTime.UtcNow;
        chain.Build(cert);

        var fatal = new List<string>();
        foreach (X509ChainStatus status in chain.ChainStatus)
        {
            if (status.Status == X509ChainStatusFlags.NoError) continue;
            if (status.Status == X509ChainStatusFlags.OfflineRevocation) continue;
            if (status.Status == X509ChainStatusFlags.RevocationStatusUnknown) continue;
            fatal.Add(status.Status.ToString());
        }

        if (fatal.Count == 0)
        {
            error = "";
            return true;
        }

        error = string.Join(", ", fatal);
        return false;
    }

    public static bool SharesIdentity(X509Certificate2 candidate, X509Certificate2 previous)
    {
        var left = new HashSet<string>(GetDnsNames(candidate), StringComparer.OrdinalIgnoreCase);
        if (left.Count == 0) return false;
        foreach (string name in GetDnsNames(previous))
        {
            if (left.Contains(name)) return true;
        }

        string a = candidate.GetNameInfo(X509NameType.SimpleName, false);
        string b = previous.GetNameInfo(X509NameType.SimpleName, false);
        return a.Length > 0 && a.Equals(b, StringComparison.OrdinalIgnoreCase);
    }
}
