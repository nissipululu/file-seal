using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SonsetSeal;

public sealed class Home(string path)
{
    public string Root { get; } = Path.GetFullPath(path);
    public string Authority => Path.Combine(Root, "authority");
    public string CaKey => Path.Combine(Authority, "ca.key.pem");
    public string CaPem => Path.Combine(Authority, "ca.pem");
    public string IssuedList => Path.Combine(Authority, "issued.json");
    public string IssuedDir => Path.Combine(Authority, "issued");
    public string RevokedList => Path.Combine(Authority, "revoked.json");
    public string Trust => Path.Combine(Root, "trust");
    public string Departments => Path.Combine(Root, "departments");
    /// <summary>Where the authority remembers its company share folder (requests in, certificates and the trust folder out).</summary>
    public string ShareFile => Path.Combine(Authority, "share.txt");
    /// <summary>On a checking computer: the highest withdrawn list number seen for each authority, so an older list cannot be slipped back in.</summary>
    public string SeenLists => Path.Combine(Root, "seen-lists.json");

    public static string DefaultPath() =>
        Environment.GetEnvironmentVariable("SONSETSEAL_HOME")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".sonsetseal");
}

public sealed record RevokedEntry(string Serial, string Name, DateTimeOffset RevokedAt, string Reason)
{
    public JsonObject ToJson() => new() { ["serial"] = Serial, ["name"] = Name, ["revoked_at"] = Time.Iso(RevokedAt), ["reason"] = Reason };

    public static RevokedEntry FromJson(JsonNode? item)
    {
        var o = item!.AsObject();
        return new(Crypto.NormSerial((string)o["serial"]!), (string)o["name"]!, Time.ParseIso((string)o["revoked_at"]!), (string)o["reason"]!);
    }
}

/// <summary>The signed list of withdrawn certificates. A checker that cannot confirm the list refuses.</summary>
public static class RevocationList
{
    public static JsonObject Create(ECDsa caKey, string caSerial, DateTimeOffset now, int days, IEnumerable<RevokedEntry> entries, int number)
    {
        var array = new JsonArray();
        foreach (var e in entries) array.Add(e.ToJson());
        var body = new JsonObject
        {
            ["v"] = 1, ["number"] = number, ["ca_serial"] = caSerial, ["issued_at"] = Time.Iso(now),
            ["next_update"] = Time.Iso(now.AddDays(days)), ["revoked"] = array
        };
        var signature = Crypto.SignEc(caKey, Canonical.Bytes(body));
        body["signature"] = Convert.ToBase64String(signature);
        return body;
    }

    /// <summary>True when the text is a list signed by this authority, whatever its dates. A list from a shared folder must pass this before it may replace the one a checking computer already has.</summary>
    internal static bool SignedBy(string json, X509Certificate2 ca)
    {
        try
        {
            var doc = (JsonObject)JsonNode.Parse(json)!;
            var signature = Convert.FromBase64String((string)doc["signature"]!);
            doc.Remove("signature");
            return Crypto.Verify(ca, Canonical.Bytes(doc), signature);
        }
        catch (Exception e) when (e is JsonException or InvalidCastException or NullReferenceException or FormatException or ArgumentException or InvalidOperationException) { return false; }
    }

    /// <summary>The number written into a list, or null when it cannot be read.</summary>
    internal static int? NumberOf(string json)
    {
        try { return (JsonNode.Parse(json) as JsonObject)?["number"] is JsonValue v && v.TryGetValue<int>(out var n) ? n : null; }
        catch (JsonException) { return null; }
    }

    /// <summary>Returns null when the list is good, otherwise the plain reason it cannot be used.</summary>
    public static string? Verify(string json, X509Certificate2 ca, DateTimeOffset now, out List<RevokedEntry> entries, out int number)
    {
        entries = [];
        number = 0;
        try
        {
            var doc = (JsonObject)JsonNode.Parse(json)!;
            var signature = Convert.FromBase64String((string)doc["signature"]!);
            doc.Remove("signature");
            if (!Crypto.Verify(ca, Canonical.Bytes(doc), signature)) return "The list of withdrawn certificates was not signed by your authority.";
            var issuedAt = Time.ParseIso((string)doc["issued_at"]!);
            var nextUpdate = Time.ParseIso((string)doc["next_update"]!);
            var listNumber = doc["number"] is { } n ? (int)n : 0;
            var parsed = doc["revoked"]!.AsArray().Select(RevokedEntry.FromJson).ToList();
            if (issuedAt > now + TimeSpan.FromMinutes(5)) return "The list of withdrawn certificates is dated in the future.";
            if (now > nextUpdate) return $"The list of withdrawn certificates ran out on {Time.Day(nextUpdate)}. Get the latest trust folder.";
            entries = parsed;
            number = listNumber;
            return null;
        }
        catch (Exception e) when (e is JsonException or InvalidCastException or NullReferenceException or FormatException or ArgumentException or InvalidOperationException)
        {
            return "The list of withdrawn certificates cannot be read.";
        }
    }
}

/// <summary>
/// The company's own certificate authority, run by its issuing department. Sonset builds this system and
/// holds nothing: no keys, no certificates, no files. A department sends only a request, never its key.
/// </summary>
public static class Authority
{
    private const string EmailProtection = "1.3.6.1.5.5.7.3.4";
    private const string DocumentSigning = "1.3.6.1.5.5.7.3.36";
    public const int MaxDays = 1095;

    private static void NeedCa(Home h)
    {
        if (!File.Exists(h.CaKey) || !File.Exists(h.CaPem))
            throw new SealException($"There is no authority in {h.Root} yet. Run 'authority init' first.");
    }

    internal static (X509Certificate2 Cert, ECDsa Key) LoadCa(Home h)
    {
        NeedCa(h);
        var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(h.CaKey));
        using var pub = X509Certificate2.CreateFromPem(File.ReadAllText(h.CaPem));
        return (pub.CopyWithPrivateKey(key), key);
    }

    public static string Init(Home h, string company, string department, int years, int listDays, DateTimeOffset now)
    {
        company = Names.CleanStrict(company, "company name");
        department = Names.CleanStrict(department, "issuing department name");
        if (File.Exists(h.CaKey))
            throw new SealException($"An authority already exists in {h.Root}. I will not overwrite it. Pick another --home folder, or move the old one away yourself.");
        Files.MakeSecretDir(h.Authority);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(Names.Build(department, company), key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var cert = request.CreateSelfSigned(now.AddMinutes(-5), now.AddYears(years));
        Files.WriteSecret(h.CaKey, key.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(h.CaPem, cert.ExportCertificatePem());
        Files.SaveJson(h.IssuedList, new JsonArray());
        Publish(h, now, listDays, null);
        return $"Created the authority '{department}, {company}'.\n" +
               $"  Secret key, never share it, never email it: {h.CaKey}\n" +
               $"  Public certificate:                         {h.CaPem}\n" +
               $"  Fingerprint to pin on checking computers:   {Crypto.Sha256Hex(cert)}\n" +
               $"  Trust folder for the checking computers:    {h.Trust}";
    }

    public static List<RevokedEntry> ReadRevoked(Home h)
    {
        if (!File.Exists(h.RevokedList)) return [];
        try
        {
            var doc = (JsonObject)JsonNode.Parse(File.ReadAllText(h.RevokedList))!;
            return doc["revoked"]!.AsArray().Select(RevokedEntry.FromJson).ToList();
        }
        catch (Exception e) when (e is JsonException or InvalidCastException or NullReferenceException or FormatException or ArgumentException)
        { throw new SealException($"The list of withdrawn certificates in {Display.Safe(h.RevokedList)} cannot be read. Restore it from a backup before publishing again."); }
    }

    private static int NextListNumber(Home h)
    {
        if (!File.Exists(h.RevokedList)) return 1;
        var doc = (JsonObject)JsonNode.Parse(File.ReadAllText(h.RevokedList))!;
        return (doc["number"] is { } n ? (int)n : 0) + 1;
    }

    public static JsonObject Publish(Home h, DateTimeOffset now, int listDays, List<RevokedEntry>? entries)
    {
        var (ca, key) = LoadCa(h);
        using var _ = ca;
        using var __ = key;
        entries ??= ReadRevoked(h);
        var list = RevocationList.Create(key, Crypto.NormSerial(ca.SerialNumber), now, listDays, entries, NextListNumber(h));
        Files.SaveJson(h.RevokedList, list);
        Directory.CreateDirectory(h.Trust);
        File.Copy(h.CaPem, Path.Combine(h.Trust, "ca.pem"), true);
        File.Copy(h.RevokedList, Path.Combine(h.Trust, "revoked.json"), true);
        CopyTrustToShare(h);
        return list;
    }

    /// <summary>The company share this authority publishes to. Stops with a plain message if there is no authority or no share yet.</summary>
    private static string RequireShare(Home h)
    {
        NeedCa(h);
        return ShareOf(h) ?? throw new SealException("No company share is set up. Run 'authority share-setup' first.");
    }

    private static string? ShareOf(Home h) => File.Exists(h.ShareFile) ? File.ReadAllText(h.ShareFile).Trim() : null;

    /// <summary>Every time the list is published, the company share gets the new trust folder too, so checking computers pick it up by themselves.</summary>
    private static void CopyTrustToShare(Home h)
    {
        if (ShareOf(h) is not { } share) return;
        try
        {
            Directory.CreateDirectory(Path.Combine(share, "Trust"));
            Files.WriteAtomic(Path.Combine(share, "Trust", "ca.pem"), File.ReadAllBytes(h.CaPem));
            Files.WriteAtomic(Path.Combine(share, "Trust", "revoked.json"), File.ReadAllBytes(h.RevokedList));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // A withdrawal that did not reach the share has not reached the checking computers, so this is an error, not a warning.
            throw new SealException($"The trust folder here is up to date, but the company share could not be updated ({Display.Safe(e.Message)}). " +
                "Checking computers will not hear of this change until you run 'authority publish' with the share reachable.");
        }
    }

    /// <summary>Sets up the company share: departments leave their requests in it, the issuing department leaves certificates and the trust folder.</summary>
    public static string ShareSetup(Home h, string share)
    {
        NeedCa(h);
        var root = Path.GetFullPath(share);
        // Everyone who can open the share could read the secret key if it were in or under it.
        if (Files.IsUnder(Files.Resolve(h.Authority), Files.Resolve(root)) || Files.IsUnder(Files.Resolve(root), Files.Resolve(h.Authority)))
            throw new SealException($"The company share cannot hold the authority's secret key, and {Display.Safe(h.Authority)} is in or around it. Pick a share folder somewhere else.");
        foreach (var sub in new[] { "Requests", "Certificates", "Trust" }) Directory.CreateDirectory(Path.Combine(root, sub));
        File.WriteAllText(h.ShareFile, root);
        CopyTrustToShare(h);
        using var ca = X509Certificate2.CreateFromPem(File.ReadAllText(h.CaPem));
        File.WriteAllText(Path.Combine(root, "README.txt"),
            "Company share for the file seal.\n\n" +
            "Requests      departments leave their certificate requests here (nothing secret in them).\n" +
            "Certificates  the issuing department leaves each approved department's certificate here (public).\n" +
            "Trust         the company's authority certificate and its list of withdrawn certificates. Updated on every publish.\n\n" +
            $"Authority fingerprint (SHA 256): {Crypto.Sha256Hex(ca)}\n" +
            "Everyone who can write to this folder can put files in it, so departments are given this fingerprint by the issuing department (setup --pin-root) and trust nothing else.\n");
        var fingerprint = Crypto.Sha256Hex(ca);
        return $"Set up the company share in {root}.\n" +
               $"  Authority fingerprint, the pin: {fingerprint}\n" +
               "  Give each department its own setup command, from you and not from the share. Only the name changes:\n" +
               $"    sonsetseal setup --share \"{root}\" --department \"NAME\" --pin-root {fingerprint}\n" +
               "  The pin means a department trusts only your authority, even if someone else can write into the share.\n" +
               "  Who may write where: departments need to write only into Requests. Make Trust and Certificates writable by the issuing department alone, or a withdrawal can be held back.\n" +
               "  Each department's setup prints a key fingerprint. Approve with: authority approve --name NAME --key KEY";
    }

    /// <summary>The requests waiting in the share, for the issuing department to look at.</summary>
    public static IEnumerable<string> Inbox(Home h)
    {
        var share = RequireShare(h);
        var files = Directory.Exists(Path.Combine(share, "Requests")) ? Directory.GetFiles(Path.Combine(share, "Requests"), "*.csr.pem").OrderBy(f => f, StringComparer.Ordinal).ToList() : [];
        if (files.Count == 0) yield return "No requests are waiting.";
        foreach (var file in files)
        {
            string line;
            try
            {
                var request = CertificateRequest.LoadSigningRequest(DecodeRequest(Files.ReadSmall(file)), HashAlgorithmName.SHA256);
                var (cn, _) = Names.Parts(request.SubjectName);
                line = $"WAITING  {Display.Safe(cn),-32} key {Crypto.GroupedFingerprint(Crypto.KeySha256Hex(request.PublicKey))}   ({Display.Safe(Path.GetFileName(file))})";
            }
            catch (Exception e) when (e is CryptographicException or System.Formats.Asn1.AsnContentException or ArgumentException or SealException or IOException or UnauthorizedAccessException)
            { line = $"UNREADABLE  {Display.Safe(Path.GetFileName(file))}"; }
            yield return line;
        }
    }

    /// <summary>
    /// One command for the issuing department: sign the waiting request of the department named and put the certificate in the share.
    /// The person types the department's name and the key fingerprint the department's own setup printed and told them. Anyone who can write
    /// to the share could swap the request for one holding their own key, so the key, not just the name, has to match what the department said.
    /// </summary>
    public static string Approve(Home h, string name, string key, int days, DateTimeOffset now)
    {
        var share = RequireShare(h);
        var typed = Names.CleanStrict(name, "department name");
        var requestFile = Path.Combine(share, "Requests", Names.Slug(typed) + ".csr.pem");
        byte[] requestBytes;
        try { requestBytes = Files.ReadSmall(requestFile); }
        catch (FileNotFoundException) { throw new SealException($"No request from '{Display.Safe(typed)}' is waiting. 'authority inbox' shows what is."); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { throw new SealException($"The request from '{Display.Safe(typed)}' cannot be read safely: {Display.Safe(e.Message)}"); }
        CertificateRequest waiting;
        try { waiting = CertificateRequest.LoadSigningRequest(DecodeRequest(requestBytes), HashAlgorithmName.SHA256); }
        catch (Exception e) when (e is CryptographicException or System.Formats.Asn1.AsnContentException or ArgumentException)
        { throw new SealException("I cannot read that request, or its signature does not check out."); }

        // Approving again after the share let the first try down finds the certificate that was already issued and puts it in the share, instead of refusing.
        string issued;
        if (FindIssued(h, Crypto.KeySha256Hex(waiting.PublicKey), typed, now) is { } already) { RequireKey(waiting.PublicKey, key); issued = already; }
        else issued = SignRequest(h, requestBytes, typed, days, now, key);
        try
        {
            Directory.CreateDirectory(Path.Combine(share, "Certificates"));
            Files.WriteAtomic(Path.Combine(share, "Certificates", Names.Slug(typed) + ".pem"), File.ReadAllBytes(issued));
            Directory.CreateDirectory(Path.Combine(share, "Requests", "handled"));
            File.Move(requestFile, Path.Combine(share, "Requests", "handled", Names.Slug(typed) + "-" + Time.Iso(now).Replace(":", "") + ".csr.pem"), true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new SealException($"The certificate was issued ({Display.Safe(issued)}) but could not be put in the company share ({Display.Safe(e.Message)}). " +
                "Run the same approve command again when the share can be reached, and it will be put there.");
        }
        return $"Approved '{typed}'. Its certificate is in the share. The department's computer installs it by itself within a few seconds.";
    }

    /// <summary>A working certificate this authority already issued for this key and name, if its file is still there.</summary>
    private static string? FindIssued(Home h, string keyHash, string name, DateTimeOffset now)
    {
        var revoked = ReadRevoked(h).Select(r => r.Serial).ToHashSet();
        foreach (var item in (JsonArray)Files.LoadJson(h.IssuedList, new JsonArray()))
        {
            var o = item!.AsObject();
            if (o["key_sha256"] is { } known && (string)known! == keyHash && string.Equals((string)o["name"]!, name, StringComparison.OrdinalIgnoreCase)
                && !revoked.Contains((string)o["serial"]!) && Time.ParseIso((string)o["not_after"]!) > now && File.Exists((string)o["file"]!))
                return (string)o["file"]!;
        }
        return null;
    }

    /// <summary>The key in a request must be the one the department told the person signing. Anyone who can write where the request waits could swap it.</summary>
    private static void RequireKey(PublicKey key, string? told)
    {
        var actual = Crypto.KeySha256Hex(key);
        var typed = System.Text.RegularExpressions.Regex.Replace(told ?? "", "[^0-9A-Fa-f]", "").ToUpperInvariant();
        if (typed.Length < 16 || !actual.StartsWith(typed, StringComparison.OrdinalIgnoreCase))
            throw new SealException($"The key does not match. The request holds key {Crypto.GroupedFingerprint(actual)}. " +
                "If that is not the key the department told you, do not approve or sign it: someone may have replaced the request.");
    }

    private static void CheckRequestedKey(PublicKey key)
    {
        switch (key.Oid.Value)
        {
            case "1.2.840.10045.2.1":
                using (var ec = ECDsa.Create())
                {
                    ec.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _);
                    var curve = ec.ExportParameters(false).Curve.Oid.Value;
                    if (curve is not ("1.2.840.10045.3.1.7" or "1.3.132.0.34")) throw new SealException("The request uses a key curve I do not accept. Use P-256 or P-384.");
                }
                break;
            case "1.2.840.113549.1.1.1":
                using (var rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _);
                    if (rsa.KeySize < 2048) throw new SealException("The request uses an RSA key shorter than 2048 bits.");
                    var exponent = new BigInteger(rsa.ExportParameters(false).Exponent!, isUnsigned: true, isBigEndian: true);
                    if (exponent < 65537 || exponent.IsEven) throw new SealException("The request uses an RSA key with a weak exponent.");
                }
                break;
            default:
                throw new SealException("The request uses a kind of key I do not accept.");
        }
    }

    private static byte[] DecodeRequest(byte[] bytes)
    {
        var text = Encoding.ASCII.GetString(bytes);
        if (!text.Contains("-----BEGIN")) return bytes;
        try
        {
            var fields = PemEncoding.Find(text);
            return Convert.FromBase64String(text[fields.Base64Data]);
        }
        catch (Exception e) when (e is ArgumentException or FormatException) { throw new SealException("I cannot read that request file."); }
    }

    /// <summary>
    /// The issuing department signs a department's request. The person signing types the department's name again,
    /// so a look alike name (a Cyrillic letter, an invisible character) cannot slip through. Returns the new certificate's path.
    /// </summary>
    /// <param name="expectedKey">The fingerprint of the key the department says it sent. The command line always requires it; the tests that build departments directly may leave it out.</param>
    public static string SignRequest(Home h, byte[] requestFile, string expectedName, int days, DateTimeOffset now, string? expectedKey = null)
    {
        var (ca, caKey) = LoadCa(h);
        using var _ = ca;
        using var __ = caKey;
        if (days > MaxDays) throw new SealException($"A department certificate can last {MaxDays} days at most.");
        CertificateRequest request;
        try { request = CertificateRequest.LoadSigningRequest(DecodeRequest(requestFile), HashAlgorithmName.SHA256); }
        catch (Exception e) when (e is CryptographicException or System.Formats.Asn1.AsnContentException or ArgumentException)
        { throw new SealException("I cannot read that request, or its signature does not check out."); }
        var (cn, _) = Names.Parts(request.SubjectName);
        var name = Names.CleanStrict(cn, "department name in the request");
        var typed = Names.CleanStrict(expectedName, "department name you typed");
        if (!string.Equals(name, typed, StringComparison.Ordinal))
            throw new SealException($"The request is for '{Display.Safe(name)}' but you said '{Display.Safe(typed)}'. Check that the request really came from that department before signing.");
        if (string.Equals(name, Names.Parts(ca.SubjectName).Common, StringComparison.OrdinalIgnoreCase))
            throw new SealException("That is the issuing department's own name. A department cannot take it.");
        if (expectedKey != null) RequireKey(request.PublicKey, expectedKey);
        CheckRequestedKey(request.PublicKey);
        if (now.AddDays(days) > ca.NotAfter) throw new SealException("That would outlive the authority's own certificate. Ask for fewer days.");

        var keyHash = Crypto.KeySha256Hex(request.PublicKey);
        var issued = (JsonArray)Files.LoadJson(h.IssuedList, new JsonArray());
        var revoked = ReadRevoked(h).Select(r => r.Serial).ToHashSet();
        foreach (var item in issued)
        {
            var o = item!.AsObject();
            if (o["key_sha256"] is { } known && (string)known! == keyHash)
                throw new SealException("This key has been certified before. A department needs a fresh key: remove the department and ask again.");
            if (string.Equals((string)o["name"]!, name, StringComparison.OrdinalIgnoreCase)
                && !revoked.Contains((string)o["serial"]!) && Time.ParseIso((string)o["not_after"]!) > now)
                throw new SealException($"'{name}' already has a working certificate. Withdraw it first if its computer was lost.");
        }

        var org = Names.Parts(ca.SubjectName).Organisation;
        var leafRequest = new CertificateRequest(Names.Build(name, org), request.PublicKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid(EmailProtection), new Oid(DocumentSigning) }, true));
        leafRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(leafRequest.PublicKey, false));
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
        var serial = RandomNumberGenerator.GetBytes(8);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x40);
        // The signature generator overload lets an elliptic curve authority issue for an RSA department key too.
        using var leaf = leafRequest.Create(ca.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey), now.AddMinutes(-5), now.AddDays(days), serial);

        Directory.CreateDirectory(h.IssuedDir);
        var serialText = Crypto.NormSerial(leaf.SerialNumber);
        var path = Path.Combine(h.IssuedDir, $"{Names.Slug(name)}-{serialText}.pem");
        File.WriteAllText(path, leaf.ExportCertificatePem());
        issued.Add(new JsonObject
        {
            ["serial"] = serialText, ["name"] = name, ["issued_at"] = Time.Iso(now), ["key_sha256"] = keyHash,
            ["not_before"] = Time.Iso(leaf.NotBefore), ["not_after"] = Time.Iso(leaf.NotAfter), ["file"] = path
        });
        Files.SaveJson(h.IssuedList, issued);
        return path;
    }

    /// <summary>Withdraws every working certificate of a department (or one by serial). A lost computer is an emergency, so no certificate is left out.</summary>
    public static string Revoke(Home h, string? name, string? serial, string? reason, int listDays, DateTimeOffset now)
    {
        NeedCa(h);
        if (serial == null && name == null) throw new SealException("Say who to withdraw with --name or --serial.");
        var issued = (JsonArray)Files.LoadJson(h.IssuedList, new JsonArray());
        var matches = issued.Select(i => i!.AsObject()).Where(o =>
            serial != null ? (string)o["serial"]! == Crypto.NormSerial(serial)
            : string.Equals((string)o["name"]!, name, StringComparison.OrdinalIgnoreCase)).ToList();
        if (matches.Count == 0) throw new SealException("I found nobody by that description.");
        var entries = ReadRevoked(h);
        var live = matches.Where(o => entries.All(e => e.Serial != (string)o["serial"]!)).ToList();
        if (live.Count == 0) throw new SealException($"'{(string)matches[0]["name"]!}' is already withdrawn.");
        var text = string.IsNullOrWhiteSpace(reason) ? "withdrawn by the authority" : reason.Trim();
        if (text.Length > 200) text = text[..200];
        foreach (var target in live)
            entries.Add(new RevokedEntry((string)target["serial"]!, (string)target["name"]!, now, text));
        Publish(h, now, listDays, entries);
        return $"Withdrew {live.Count} certificate{(live.Count == 1 ? "" : "s")} of '{(string)live[0]["name"]!}'. Files they sealed will now fail the check.\nCopy {h.Trust} to every checking computer.";
    }

    public static IEnumerable<string> List(Home h, DateTimeOffset now)
    {
        NeedCa(h);
        var revoked = ReadRevoked(h).Select(r => r.Serial).ToHashSet();
        var issued = (JsonArray)Files.LoadJson(h.IssuedList, new JsonArray());
        if (issued.Count == 0) yield return "No certificates issued yet.";
        foreach (var item in issued)
        {
            var o = item!.AsObject();
            var status = revoked.Contains((string)o["serial"]!) ? "WITHDRAWN" : Time.ParseIso((string)o["not_after"]!) < now ? "EXPIRED" : "ACTIVE";
            yield return $"{status,-10}{Display.Safe((string)o["name"]!),-28}good until {Time.Day(Time.ParseIso((string)o["not_after"]!))}   serial {(string)o["serial"]!}";
        }
    }
}
