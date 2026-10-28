using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>Who signs a file. The secret key never leaves its home (the computer's own store, or a key file in tests).</summary>
public abstract class SigningIdentity
{
    public abstract X509Certificate2 Certificate { get; }
    public virtual IReadOnlyList<X509Certificate2> Chain => [];
    public abstract byte[] Sign(byte[] data);
}

/// <summary>A key held in memory or a file, with its certificate. Used by tests and by the key file option.</summary>
public sealed class KeyIdentity(X509Certificate2 certificate, AsymmetricAlgorithm key, IEnumerable<X509Certificate2>? chain = null) : SigningIdentity
{
    private readonly List<X509Certificate2> _chain = chain?.ToList() ?? [];
    public override X509Certificate2 Certificate { get; } = certificate;
    public override IReadOnlyList<X509Certificate2> Chain => _chain;

    public override byte[] Sign(byte[] data) => key switch
    {
        ECDsa ec => Crypto.SignEc(ec, data),
        RSA rsa => Crypto.SignRsa(rsa, data),
        _ => throw new SealException("That kind of key cannot sign.")
    };
}

/// <summary>
/// A key and certificate that already sit in the user's own certificate store, for example one that
/// a company's Active Directory Certificate Services handed out automatically. Mode B. Not proven on
/// a real AD CS yet.
/// </summary>
public sealed class StoreCertIdentity : SigningIdentity
{
    private readonly X509Certificate2 _cert;
    private readonly List<X509Certificate2> _chain = [];

    private StoreCertIdentity(X509Certificate2 cert) { _cert = cert; }
    public override X509Certificate2 Certificate => _cert;
    public override IReadOnlyList<X509Certificate2> Chain => _chain;

    public static StoreCertIdentity FromStore(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint.Replace(" ", ""), false);
        if (found.Count != 1) throw new SealException("I cannot find that certificate in this computer's store.");
        var identity = new StoreCertIdentity(found[0]);
        if (!found[0].HasPrivateKey) throw new SealException("That certificate has no key on this computer, so it cannot seal.");
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true; // sealing never makes this computer go and fetch anything
        chain.Build(found[0]);
        for (var i = 1; i < chain.ChainElements.Count - 1; i++)
            identity._chain.Add(X509CertificateLoader.LoadCertificate(chain.ChainElements[i].Certificate.RawData));
        return identity;
    }

    public override byte[] Sign(byte[] data)
    {
        using var ec = _cert.GetECDsaPrivateKey();
        if (ec != null) return Crypto.SignEc(ec, data);
        using var rsa = _cert.GetRSAPrivateKey();
        if (rsa != null) return Crypto.SignRsa(rsa, data);
        throw new SealException("That certificate's key is not a kind that can sign here.");
    }
}

/// <summary>
/// The department's key lives in the computer's own protected store (Keychain on a Mac, the user's
/// certificate store on Windows). It is kept as a key that cannot be exported, so it cannot be copied
/// off the computer, and it unlocks with the person's normal login: no password, no prompt.
/// </summary>
internal static class OsKeyStore
{
    public static string Persist(ECDsa key, string label, DateTimeOffset now)
    {
        var request = new CertificateRequest(Names.Build($"Sonset seal key for {label}", null), key, HashAlgorithmName.SHA256);
        using var vessel = request.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(30));
        var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        var image = vessel.Export(X509ContentType.Pfx, password);
        using var imported = X509CertificateLoader.LoadPkcs12(image, password, X509KeyStorageFlags.PersistKeySet);
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        if (store.Certificates.Find(X509FindType.FindByThumbprint, imported.Thumbprint, false).Count == 0) store.Add(imported);
        return imported.Thumbprint;
    }

    public static X509Certificate2? Find(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
        return found.Count == 1 ? found[0] : null;
    }

    public static void Remove(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        foreach (var c in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false))
        {
            if (OperatingSystem.IsWindows()) DeleteWindowsKey(c);
            store.Remove(c);
        }
    }

    /// <summary>On Windows, removing the certificate leaves its persisted key behind; the key has to be deleted itself. Not tried on Windows yet.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void DeleteWindowsKey(X509Certificate2 certificate)
    {
        try
        {
            using var key = certificate.GetECDsaPrivateKey();
            if (key is ECDsaCng cng) cng.Key.Delete();
        }
        catch (Exception e) when (e is CryptographicException or NotSupportedException) { /* the certificate is removed regardless */ }
    }
}

internal sealed class OsKeyIdentity(X509Certificate2 certificate, string thumbprint) : SigningIdentity
{
    public override X509Certificate2 Certificate { get; } = certificate;

    public override byte[] Sign(byte[] data)
    {
        using var vessel = OsKeyStore.Find(thumbprint)
            ?? throw new SealException("This department's key is not in this computer's store any more. Ask the issuing department for a new certificate.");
        using var key = vessel.GetECDsaPrivateKey() ?? throw new SealException("This department's key cannot be used on this computer.");
        return Crypto.SignEc(key, data);
    }
}

/// <summary>
/// A department makes its own key and a request. Only the request travels to the issuing department;
/// the certificate comes back public. Sonset never sees any of it.
/// </summary>
public static class Department
{
    private static string Dir(Home h, string slug) => Path.Combine(h.Departments, slug);

    private static JsonObject Identity(Home h, string slug)
    {
        var path = Path.Combine(Dir(h, slug), "identity.json");
        if (!File.Exists(path)) throw new SealException($"There is no department '{slug}' on this computer. Run 'department request' first.");
        return (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
    }

    private static string ResolveSlug(Home h, string? nameOrSlug)
    {
        if (!Directory.Exists(h.Departments)) throw new SealException("No department is set up on this computer. Run 'department request' first.");
        var all = Directory.GetDirectories(h.Departments).Select(Path.GetFileName).Where(n => n != null).Select(n => n!).ToList();
        if (nameOrSlug != null)
        {
            var slug = Names.Slug(nameOrSlug);
            if (!all.Contains(slug)) throw new SealException($"There is no department '{nameOrSlug}' on this computer.");
            return slug;
        }
        if (all.Count == 1) return all[0];
        throw new SealException(all.Count == 0 ? "No department is set up on this computer." : "More than one department is set up here. Say which with --department.");
    }

    public static string Request(Home h, string name, bool keyFile, DateTimeOffset now)
    {
        name = Names.CleanStrict(name, "department name");
        var slug = Names.Slug(name);
        var dir = Dir(h, slug);
        if (Directory.Exists(dir)) throw new SealException($"A department called '{name}' is already set up here.");
        // Only the Mac Keychain and the Windows certificate store are a protected place for a key. Anywhere else the key would be a plain file.
        if (!keyFile && !OperatingSystem.IsMacOS() && !OperatingSystem.IsWindows())
            throw new SealException("This computer has no protected key store the tool can use. Add --key-file to keep the key in a file in the settings folder.");
        Files.MakeSecretDir(h.Departments);
        Files.MakeSecretDir(dir);
        string? stored = null;
        try
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var csr = new CertificateRequest(Names.Build(name, null), key, HashAlgorithmName.SHA256).CreateSigningRequest();
            var identity = new JsonObject { ["name"] = name, ["slug"] = slug, ["created"] = Time.Iso(now) };
            if (keyFile)
            {
                Files.WriteSecret(Path.Combine(dir, "key.pem"), key.ExportPkcs8PrivateKeyPem());
                identity["storage"] = "file";
            }
            else
            {
                identity["storage"] = "os";
                stored = OsKeyStore.Persist(key, name, now);
                identity["key_thumbprint"] = stored;
            }
            File.WriteAllText(Path.Combine(dir, "request.csr.pem"), PemEncoding.WriteString("CERTIFICATE REQUEST", csr) + "\n");
            Files.SaveJson(Path.Combine(dir, "identity.json"), identity);
        }
        catch
        {
            // A setup that fails halfway must not leave a key behind in the computer's store.
            if (stored != null) try { OsKeyStore.Remove(stored); } catch (Exception e) when (e is CryptographicException or IOException) { }
            Directory.Delete(dir, true);
            throw;
        }
        var requestPath = Path.Combine(dir, "request.csr.pem");
        return $"Made the key for '{name}' and kept it " + (keyFile ? "in a key file here." : "in this computer's protected store. It cannot be copied off.") + "\n" +
               $"  Send this request to the issuing department. It holds no secret: {requestPath}\n" +
               $"  Tell the issuing department this key fingerprint, in person or by phone, when you ask them to approve: {RequestKeyFingerprint(h, name)}\n" +
               "  When the certificate comes back, run 'department install'.";
    }

    /// <summary>The fingerprint of the key in this department's own request, for the department to tell the issuing department so the right key is approved.</summary>
    public static string RequestKeyFingerprint(Home h, string name)
    {
        var path = Path.Combine(Dir(h, Names.Slug(name)), "request.csr.pem");
        if (!File.Exists(path)) throw new SealException($"There is no request for '{name}' on this computer.");
        var request = CertificateRequest.LoadSigningRequest(Convert.FromBase64String(string.Concat(File.ReadAllLines(path).Where(l => !l.StartsWith("-----")))), HashAlgorithmName.SHA256);
        return Crypto.GroupedFingerprint(Crypto.KeySha256Hex(request.PublicKey));
    }

    private static X509Certificate2 ReadCert(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        try { return text.Contains("-----BEGIN") ? X509Certificate2.CreateFromPem(text) : X509CertificateLoader.LoadCertificate(bytes); }
        catch (Exception e) when (e is CryptographicException or System.Formats.Asn1.AsnContentException or ArgumentException)
        { throw new SealException("I cannot read that certificate file."); }
    }

    /// <summary>True when the certificate was issued by the given authority certificate, judged today and offline.</summary>
    private static bool IssuedBy(X509Certificate2 leaf, X509Certificate2 authority)
    {
        using var chain = new X509Chain();
        var policy = chain.ChainPolicy;
        policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        policy.CustomTrustStore.Add(authority);
        policy.RevocationMode = X509RevocationMode.NoCheck;
        policy.DisableCertificateDownloads = true;
        return chain.Build(leaf);
    }

    /// <param name="issuer">When given, the certificate must have been issued by it. A certificate that arrives through a shared folder is always checked this way.</param>
    public static string Install(Home h, string? nameOrSlug, byte[] certFile, X509Certificate2? issuer = null)
    {
        var slug = ResolveSlug(h, nameOrSlug);
        var identity = Identity(h, slug);
        using var cert = ReadCert(certFile);
        byte[] keyInfo;
        if ((string)identity["storage"]! == "file")
        {
            using var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(Path.Combine(Dir(h, slug), "key.pem")));
            keyInfo = key.ExportSubjectPublicKeyInfo();
        }
        else
        {
            using var vessel = OsKeyStore.Find((string)identity["key_thumbprint"]!)
                ?? throw new SealException("This department's key is not in this computer's store.");
            keyInfo = vessel.PublicKey.ExportSubjectPublicKeyInfo();
        }
        if (!keyInfo.AsSpan().SequenceEqual(cert.PublicKey.ExportSubjectPublicKeyInfo()))
            throw new SealException("That certificate was not made for this department's key.");
        // The public key is public: anyone could get a certificate for it from some other authority. The name and the issuer have to be right too.
        if (!string.Equals(Names.Parts(cert.SubjectName).Common, (string)identity["name"]!, StringComparison.Ordinal))
            throw new SealException("That certificate is for a different department name.");
        if (issuer != null && !IssuedBy(cert, issuer))
            throw new SealException("That certificate was not issued by the authority this department was told to trust.");
        Files.WriteAtomic(Path.Combine(Dir(h, slug), "cert.pem"), cert.ExportCertificatePem());
        identity["installed"] = true;
        Files.SaveJson(Path.Combine(Dir(h, slug), "identity.json"), identity);
        var (cn, org) = Names.Parts(cert.SubjectName);
        return $"Installed the certificate for '{Display.Safe(Names.Label(cn, org))}', good until {Time.Day(cert.NotAfter)}. This department can seal files now.";
    }

    public static bool Exists(Home h, string name) => File.Exists(Path.Combine(Dir(h, Names.Slug(name)), "identity.json"));

    public static bool HasCertificate(Home h, string name) => File.Exists(Path.Combine(Dir(h, Names.Slug(name)), "cert.pem"));

    /// <summary>Leaves this department's request in the company share for the issuing department to see. Nothing secret is in it.</summary>
    public static string PublishRequest(Home h, string name, string share)
    {
        var slug = Names.Slug(name);
        var source = Path.Combine(Dir(h, slug), "request.csr.pem");
        if (!File.Exists(source)) throw new SealException($"There is no request for '{name}' on this computer.");
        var target = Path.Combine(Path.GetFullPath(share), "Requests", slug + ".csr.pem");
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        Files.WriteAtomic(target, File.ReadAllBytes(source));
        return target;
    }

    /// <summary>
    /// If the issuing department has approved this department, takes the certificate from the share and installs it, but only when the authority on
    /// the share is one of the pinned ones and issued the certificate. Nothing is installed because a file merely turned up in a shared folder.
    /// Not approved yet is not a problem (Problem stays null); anything else that stops it is explained.
    /// </summary>
    public static (bool Installed, string? Problem) TryInstallFromShare(Home h, string name, string share, IReadOnlyCollection<string> pins)
    {
        if (HasCertificate(h, name)) return (true, null);
        var slug = Names.Slug(name);
        var root = Path.GetFullPath(share);
        var certFile = Path.Combine(root, "Certificates", slug + ".pem");
        if (!File.Exists(certFile)) return (false, null);
        if (pins.Count == 0)
            return (false, "No authority is pinned for this department, so the certificate in the share is not trusted. Run setup again with --pin-root.");
        try
        {
            using var authority = X509Certificate2.CreateFromPem(Files.ReadSmallText(Path.Combine(root, "Trust", "ca.pem")));
            if (!pins.Contains(Crypto.Sha256Hex(authority)))
                return (false, "The authority in the share is not the one pinned for this department, so nothing was installed.");
            Install(h, slug, Files.ReadSmall(certFile), authority);
            return (true, null);
        }
        catch (SealException e) { return (false, e.Message); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
        { return (false, "The certificate or the authority in the share cannot be read safely: " + Display.Safe(e.Message)); }
    }

    public static SigningIdentity Load(Home h, string? nameOrSlug)
    {
        var slug = ResolveSlug(h, nameOrSlug);
        var identity = Identity(h, slug);
        var certPath = Path.Combine(Dir(h, slug), "cert.pem");
        if (!File.Exists(certPath))
            throw new SealException($"'{(string)identity["name"]!}' has no certificate yet. Send its request to the issuing department, then run 'department install'.");
        var cert = X509Certificate2.CreateFromPem(File.ReadAllText(certPath));
        if ((string)identity["storage"]! == "file")
        {
            var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(Path.Combine(Dir(h, slug), "key.pem")));
            return new KeyIdentity(cert, key);
        }
        return new OsKeyIdentity(cert, (string)identity["key_thumbprint"]!);
    }

    public static IEnumerable<string> List(Home h)
    {
        if (!Directory.Exists(h.Departments)) { yield return "No department is set up on this computer."; yield break; }
        foreach (var dir in Directory.GetDirectories(h.Departments).OrderBy(d => d, StringComparer.Ordinal))
        {
            var id = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "identity.json")))!;
            var state = File.Exists(Path.Combine(dir, "cert.pem")) ? "READY" : "WAITING FOR CERTIFICATE";
            yield return $"{state,-24}{(string)id["name"]!}   key kept in {((string)id["storage"]! == "os" ? "the computer's store" : "a key file")}";
        }
    }

    /// <summary>Takes the department off this computer: its key leaves the store and its folder is deleted.</summary>
    public static void Remove(Home h, string? nameOrSlug)
    {
        var slug = ResolveSlug(h, nameOrSlug);
        var identity = Identity(h, slug);
        if ((string)identity["storage"]! == "os") OsKeyStore.Remove((string)identity["key_thumbprint"]!);
        Directory.Delete(Dir(h, slug), true);
    }
}
