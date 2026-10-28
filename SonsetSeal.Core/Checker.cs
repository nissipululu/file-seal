using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SonsetSeal;

public sealed record CheckDetails(string Signer, string? Organisation, string IssuedBy, string? IssuerOrganisation, string Authority,
    DateTimeOffset SealedAt, DateTimeOffset CertificateValidUntil, IReadOnlyList<KeyValuePair<string, string>> Claims, string Note);

public sealed record CheckResult(string File, string Status, string Reason, CheckDetails? Details = null)
{
    public bool Ok => Status == "VERIFIED";
}

/// <summary>
/// What a checking computer trusts. Two modes. A folder: the company's own authority certificate and its signed list of
/// withdrawn certificates (Mode A). Or the computer's own trusted roots, pinned to the company's root so that nobody
/// holding some other public certificate can seal as the company (Mode B, not proven on a real AD CS yet).
/// </summary>
public sealed class TrustPolicy
{
    public bool UseSystem { get; private init; }
    public List<X509Certificate2> Roots { get; } = [];
    public HashSet<string> Pins { get; private init; } = [];
    public string? Problem { get; private set; }
    public Dictionary<string, RevokedEntry> Revoked { get; private set; } = [];

    internal static HashSet<string> NormalizePins(IEnumerable<string>? pins)
    {
        // A pin that is empty or not hex is an error, never a pin that quietly goes away: that would leave the folder trusted with no pin at all.
        var set = (pins ?? []).Select(p => Regex.Replace(p, "[^0-9A-Fa-f]", "").ToUpperInvariant()).ToList();
        if (set.Any(p => p.Length != 64)) throw new SealException("A root fingerprint is 64 hexadecimal characters (SHA 256).");
        return set.ToHashSet();
    }

    /// <param name="pinRoot">Optional fingerprints. If given, the authority in the folder must be one of them, or the folder is refused.</param>
    /// <param name="seenStatePath">Where this computer remembers the highest withdrawn list number it has seen, so an older list cannot be slipped back in.</param>
    public static TrustPolicy FromFolder(string folder, DateTimeOffset now, IEnumerable<string>? pinRoot = null, string? seenStatePath = null)
    {
        var caPath = Path.Combine(folder, "ca.pem");
        if (!File.Exists(caPath)) throw new SealException($"There is no ca.pem in the trust folder {folder}. A check cannot run without it.");
        X509Certificate2 root;
        try { root = X509Certificate2.CreateFromPem(File.ReadAllText(caPath)); }
        catch (Exception e) when (e is CryptographicException or ArgumentException) { throw new SealException($"I cannot read ca.pem in {folder}."); }
        var pins = NormalizePins(pinRoot);
        var fingerprint = Crypto.Sha256Hex(root);
        if (pins.Count > 0 && !pins.Contains(fingerprint))
            throw new SealException($"The authority in the trust folder is not the one you pinned. Its fingerprint is {fingerprint}. Do not use this folder until you know why.");
        var policy = new TrustPolicy();
        policy.Roots.Add(root);
        var listPath = Path.Combine(folder, "revoked.json");
        if (!File.Exists(listPath)) { policy.Problem = "There is no list of withdrawn certificates in the trust folder."; return policy; }
        policy.Problem = RevocationList.Verify(File.ReadAllText(listPath), root, now, out var entries, out var number);
        if (policy.Problem != null) return policy;
        policy.Revoked = entries.ToDictionary(e => e.Serial);
        if (seenStatePath != null) policy.RememberList(seenStatePath, fingerprint, number);
        return policy;
    }

    private void RememberList(string statePath, string rootFingerprint, int number)
    {
        try
        {
            var state = new JsonObject();
            if (File.Exists(statePath))
            {
                try { state = JsonNode.Parse(File.ReadAllText(statePath)) as JsonObject ?? throw new JsonException("not an object"); }
                catch (JsonException)
                {
                    // A damaged memory must not switch the protection off for good: keep the damaged file to look at and start again from this list.
                    File.Move(statePath, statePath + ".damaged", overwrite: true);
                    state = new JsonObject();
                }
            }
            var seen = state[rootFingerprint] is JsonValue stored && stored.TryGetValue<int>(out var storedNumber) ? storedNumber : 0;
            if (number < seen)
            {
                Problem = $"This list of withdrawn certificates (number {number}) is older than one this computer has already seen (number {seen}). Get the latest trust folder.";
                Revoked = [];
                return;
            }
            if (number > seen)
            {
                state[rootFingerprint] = number;
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(statePath))!);
                Files.WriteAtomic(statePath, state.ToJsonString());
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* remembering is best effort */ }
    }

    public static TrustPolicy FromSystem(IEnumerable<string> pinnedRootSha256)
    {
        var pins = NormalizePins(pinnedRootSha256);
        if (pins.Count == 0)
            throw new SealException("Using the computer's own trusted roots needs --pin-root with the company root's SHA 256 fingerprint. Without it, anyone holding any public certificate could seal as the company.");
        return new TrustPolicy { UseSystem = true, Pins = pins };
    }
}

public static class Checker
{
    private static readonly string[] SigningUses =
    [
        "1.3.6.1.5.5.7.3.4",       // e-mail protection
        "1.3.6.1.5.5.7.3.36",      // document signing
        "1.3.6.1.4.1.311.10.3.12", // Microsoft document signing
        "2.5.29.37.0"              // any purpose
    ];

    /// <summary>Tests only: runs after the file has been hashed, before the final look. Lets a test change the file mid check.</summary>
    internal static Action<string>? AfterHashHook;

    /// <summary>More certificates than this in a seal's chain is not a real seal. A crafted one could otherwise make the chain engine do a great deal of work.</summary>
    private const int MaxChainLength = 8;

    /// <summary>No real seal is older than this tool, and an absurd date must never reach the operating system's certificate code.</summary>
    private static readonly DateTimeOffset EarliestSealDate = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private sealed record Parsed(byte[] SignedCanon, string CertPem, List<string> ChainPems, byte[] Signature, DateTimeOffset SealedAt,
        long FileSize, string FileSha256, string SignerSha256, Dictionary<string, string> Claims);

    private static DamagedSealException BadShape() => new("The seal is not in the expected shape.");

    /// <summary>A seal made by an older version of this tool (or by something else): well formed, but not a kind this check accepts.</summary>
    private sealed class OldFormatException : Exception;

    private static Parsed Parse(byte[] payload)
    {
        try
        {
            using var doc = JsonDocument.Parse(payload);
            var env = doc.RootElement;
            if (env.ValueKind != JsonValueKind.Object) throw BadShape();
            Canonical.Of(env); // throws if any object anywhere in the seal repeats a field name
            var signed = env.GetProperty("signed");
            if (signed.ValueKind != JsonValueKind.Object || !signed.GetProperty("v").TryGetInt32(out var version)) throw BadShape();
            if (version == 1) throw new OldFormatException();
            if (version != Sealer.Version) throw new DamagedSealException("This seal was made by a different version of the tool. Update this program, or ask for a seal made with this version.");
            var sha = signed.GetProperty("file_sha256").GetString();
            if (sha == null || !Regex.IsMatch(sha, "^[0-9a-f]{64}$")) throw BadShape();
            var sizeElement = signed.GetProperty("file_size");
            if (sizeElement.ValueKind != JsonValueKind.Number || !sizeElement.TryGetInt64(out var size)) throw BadShape();
            var claimsElement = signed.GetProperty("claims");
            if (claimsElement.ValueKind != JsonValueKind.Object) throw BadShape();
            var claims = new Dictionary<string, string>();
            foreach (var p in claimsElement.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.String) throw BadShape();
                claims[p.Name] = p.Value.GetString()!;
            }
            var signerSha = signed.GetProperty("signer_sha256").GetString();
            if (signerSha == null || !Regex.IsMatch(signerSha, "^[0-9a-fA-F]{64}$")) throw BadShape();
            var sealedAt = Time.ParseIso(signed.GetProperty("sealed_at").GetString()!);
            var signature = Convert.FromBase64String(env.GetProperty("signature").GetString()!);
            var cert = env.GetProperty("cert").GetString()!;
            var chain = new List<string>();
            if (env.TryGetProperty("chain", out var chainElement))
            {
                if (chainElement.ValueKind != JsonValueKind.Array) throw BadShape();
                foreach (var item in chainElement.EnumerateArray()) chain.Add(item.GetString()!);
                if (chain.Count > MaxChainLength) throw new DamagedSealException("The seal carries more certificates than any real one does.");
            }
            foreach (var pem in chain.Append(cert))
                if (Regex.Matches(pem, "-----BEGIN CERTIFICATE-----").Count != 1) throw new DamagedSealException("The seal should carry exactly one certificate in each place.");
            return new Parsed(Encoding.ASCII.GetBytes(Canonical.Of(signed)), cert, chain, signature, sealedAt, size, sha, signerSha, claims);
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException or NullReferenceException)
        {
            throw new DamagedSealException("The seal cannot be read.");
        }
    }

    private static X509Chain NewChain(X509Certificate2Collection extras, TrustPolicy trust, DateTimeOffset at, bool online)
    {
        var chain = new X509Chain();
        var policy = chain.ChainPolicy;
        policy.VerificationTime = at.UtcDateTime;
        policy.DisableCertificateDownloads = true; // a seal can never make this computer go and fetch something from the internet
        policy.ExtraStore.AddRange(extras);
        if (trust.UseSystem)
        {
            policy.TrustMode = X509ChainTrustMode.System;
            policy.RevocationMode = online ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
            policy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            policy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        }
        else
        {
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var root in trust.Roots) policy.CustomTrustStore.Add(root);
            policy.RevocationMode = X509RevocationMode.NoCheck;
        }
        return chain;
    }

    private static X509ChainStatusFlags FlagsOf(X509Chain chain) => chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, (all, one) => all | one.Status);

    private static (string Status, string Reason)? VerifyChain(X509Certificate2 leaf, X509Certificate2Collection extras, TrustPolicy trust, DateTimeOffset at, out X509Certificate2? root)
    {
        root = null;
        using var chain = NewChain(extras, trust, at, online: false);
        var built = chain.Build(leaf);
        var flags = FlagsOf(chain);

        if (built)
        {
            root = X509CertificateLoader.LoadCertificate(chain.ChainElements[^1].Certificate.RawData);
            if (trust.UseSystem)
            {
                if (!trust.Pins.Contains(Crypto.Sha256Hex(root)))
                    return ("NOT_TRUSTED", "The seal was made by someone the company does not trust (the certificate chain ends at a different root).");
                // Only now, with the chain proven to end at the company's own root, is the computer allowed to ask about withdrawals online.
                using var online = NewChain(extras, trust, at, online: true);
                online.Build(leaf);
                var onlineFlags = FlagsOf(online);
                if (onlineFlags.HasFlag(X509ChainStatusFlags.Revoked)) return ("REVOKED", "The company withdrew this signer's certificate.");
                if ((onlineFlags & (X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation)) != 0)
                    return ("CANNOT_CONFIRM", "The company's list of withdrawn certificates could not be reached, so this file cannot be confirmed.");
            }
            return null;
        }
        // Who made it comes first: an untrusted chain is refused as untrusted whatever else is also wrong with it.
        if ((flags & (X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain)) != 0)
            return ("NOT_TRUSTED", "The seal was made by someone your trust list does not recognise.");
        if ((flags & X509ChainStatusFlags.NotSignatureValid) != 0)
            return ("NOT_TRUSTED", "The seal was made by someone your trust list does not recognise (the signing certificate was not issued by your authority: the signature on it does not match).");
        if (at < leaf.NotBefore) return ("NOT_TRUSTED", "The signing certificate was not valid yet on the day the file says it was sealed.");
        if (at > leaf.NotAfter) return ("NOT_TRUSTED", "The signing certificate had already expired on the day the file says it was sealed.");
        if ((flags & X509ChainStatusFlags.NotTimeValid) != 0) return ("NOT_TRUSTED", "A certificate in the chain was not valid on the day the file says it was sealed.");
        if ((flags & (X509ChainStatusFlags.NotValidForUsage | X509ChainStatusFlags.InvalidBasicConstraints)) != 0)
            return ("NOT_TRUSTED", "The signing certificate is not allowed to sign documents.");
        return ("NOT_TRUSTED", "The signing certificate does not check out.");
    }

    private static string? SigningProblem(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext is X509BasicConstraintsExtension { CertificateAuthority: true })
                return "The signing certificate is an authority's own, which may not sign files.";
            if (ext is X509KeyUsageExtension ku && (ku.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)) == 0)
                return "The signing certificate is not allowed to sign documents.";
            if (ext is X509EnhancedKeyUsageExtension eku && !eku.EnhancedKeyUsages.Cast<Oid>().Any(o => SigningUses.Contains(o.Value)))
                return "The signing certificate is not allowed to sign documents.";
        }
        return null;
    }

    /// <summary>Opens the file once, unbuffered. An open that hangs (a pipe, a stuck network drive) is given up after a few seconds.</summary>
    private static FileStream? OpenForCheck(string path, out string? problem)
    {
        problem = null;
        try
        {
            if (!Files.RunWithin(path, () => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 0), out var fs))
            { problem = "I could not open this in time. It may not be an ordinary file."; return null; }
            if (!fs!.CanSeek) { fs.Dispose(); problem = "This is not an ordinary file."; return null; }
            return fs;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            problem = "I could not read the file.";
            return null;
        }
    }

    /// <summary>
    /// Whether the file ends with a seal marker (a damaged seal counts: it is still a sealed file that must not be trusted).
    /// A cheap look at the last bytes only. Null when the file cannot be read in time.
    /// </summary>
    public static bool? CarriesSeal(string path)
    {
        var fs = OpenForCheck(path, out _);
        if (fs == null) return null;
        using (fs)
        {
            try { return SealFormat.ReadTrailer(fs) != null; }
            catch (DamagedSealException) { return true; }
            catch (IOException) { return null; }
        }
    }

    public static CheckResult Check(string path, TrustPolicy trust, DateTimeOffset now)
    {
        var fs = OpenForCheck(path, out var problem);
        if (fs == null) return new(path, "UNREADABLE", problem!);
        try
        {
            using (fs) return CheckStream(path, fs, trust, now);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new(path, "UNREADABLE", "I could not read the file.");
        }
        // Whatever a crafted file makes the operating system's certificate code do, the answer is a refusal. It is never a crash and never a pass.
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return new(path, "DAMAGED", "The seal on this file could not be read safely, so the file is refused.");
        }
    }

    private static CheckResult CheckStream(string path, FileStream fs, TrustPolicy trust, DateTimeOffset now)
    {
        SealFormat.Trailer? found;
        long totalLength;
        // What the path held when it was opened: if the path holds something else when the hash is done, the verdict is not about that file.
        var openedWith = new FileInfo(path);
        var openedLength = openedWith.Length;
        var openedWritten = openedWith.LastWriteTimeUtc;
        try { totalLength = fs.Length; found = SealFormat.ReadTrailer(fs); }
        catch (DamagedSealException e) { return new(path, "DAMAGED", "The seal on this file is damaged. " + e.Message); }
        catch (IOException) { return new(path, "UNREADABLE", "I could not read the file."); }
        if (found == null) return new(path, "NO_SEAL", "This file carries no seal.");

        Parsed seal;
        try { seal = Parse(found.Payload); }
        catch (DamagedSealException e) { return new(path, "DAMAGED", "The seal on this file is damaged. " + e.Message); }
        catch (OldFormatException) { return new(path, "NOT_TRUSTED", "This seal is in an older format that this check does not accept. Ask the department to seal the file again."); }
        if (seal.SealedAt > now + TimeSpan.FromMinutes(5)) return new(path, "NOT_TRUSTED", "The seal is dated in the future, so it cannot be right.");
        if (seal.SealedAt < EarliestSealDate) return new(path, "NOT_TRUSTED", "The seal is dated before this tool existed, so it cannot be right.");

        X509Certificate2 leaf;
        var extras = new X509Certificate2Collection();
        try
        {
            leaf = X509Certificate2.CreateFromPem(seal.CertPem);
            foreach (var pem in seal.ChainPems) extras.Add(X509Certificate2.CreateFromPem(pem));
        }
        catch (CryptographicException) { return new(path, "DAMAGED", "The seal on this file is damaged. The certificate cannot be read."); }

        using (leaf)
        {
            if (!string.Equals(seal.SignerSha256, Crypto.Sha256Hex(leaf), StringComparison.OrdinalIgnoreCase))
                return new(path, "SEAL_BROKEN", "The signing certificate was swapped after the file was sealed.");

            var chainProblem = VerifyChain(leaf, extras, trust, seal.SealedAt, out var root);
            if (chainProblem is { } cp) return new(path, cp.Status, cp.Reason);
            var usage = SigningProblem(leaf);
            if (usage != null) return new(path, "NOT_TRUSTED", usage);

            var (cn, org) = Names.Parts(leaf.SubjectName);
            if (!trust.UseSystem)
            {
                if (trust.Problem != null) return new(path, "CANNOT_CONFIRM", trust.Problem + " Without it nobody can tell whether the signer was withdrawn.");
                if (trust.Revoked.TryGetValue(Crypto.NormSerial(leaf.SerialNumber), out var entry))
                    return new(path, "REVOKED", $"{Display.Safe(cn)} was withdrawn as a signer on {Time.Day(entry.RevokedAt)} ({Display.Safe(entry.Reason)}).");
            }
            if (!Crypto.Verify(leaf, seal.SignedCanon, seal.Signature))
                return new(path, "SEAL_BROKEN", "The information inside the seal was altered, so the seal no longer matches its signer.");
            if (Fields.StrictProblem(seal.Claims) is { } rules)
                return new(path, "NOT_TRUSTED", "The seal is genuine, but its fields break the rules. " + rules);

            // Hash the file through the same open handle, then look once more: the file must still be exactly what was read first.
            bool same;
            try
            {
                same = seal.FileSize == found.BodyLength && SealFormat.HashPrefix(fs, found.BodyLength) == seal.FileSha256;
                AfterHashHook?.Invoke(path);
                if (same)
                {
                    var again = SealFormat.ReadTrailer(fs);
                    bool pathSame;
                    try { var onDisk = new FileInfo(path); pathSame = onDisk.Exists && onDisk.Length == openedLength && onDisk.LastWriteTimeUtc == openedWritten; }
                    catch (IOException) { pathSame = false; }
                    if (!pathSame || fs.Length != totalLength || again == null || again.BodyLength != found.BodyLength || !again.Payload.AsSpan().SequenceEqual(found.Payload))
                        return new(path, "CHANGED", "The file changed while it was being checked.");
                }
            }
            catch (Exception e) when (e is IOException or DamagedSealException) { same = false; }
            if (!same) return new(path, "CHANGED", "The file was changed after it was sealed.");

            var (issuerCn, issuerOrg) = Names.Parts(leaf.IssuerName);
            var note = now > leaf.NotAfter ? " (the certificate has expired since, but it was valid when the file was sealed)" : "";
            var authority = Crypto.ShortFingerprint(root ?? leaf);
            var details = new CheckDetails(cn ?? "unknown", org, issuerCn ?? "unknown", issuerOrg, authority, seal.SealedAt, leaf.NotAfter,
                Fields.InOrder(seal.Claims).ToList(), note.Trim());
            return new(path, "VERIFIED", "The seal is genuine and the file has not changed since." + note, details);
        }
    }

    /// <summary>Every file, dotfiles included. Nothing is skipped quietly.</summary>
    public static IEnumerable<string> Collect(IEnumerable<string> paths)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.None, IgnoreInaccessible = true };
        foreach (var raw in paths)
        {
            if (Directory.Exists(raw))
            {
                foreach (var f in Directory.EnumerateFiles(raw, "*", options).OrderBy(f => f, StringComparer.Ordinal)) yield return f;
            }
            else yield return raw;
        }
    }

    public static string Render(CheckResult r, bool colour)
    {
        static string Paint(string text, string code, bool on) => on ? $"\u001b[{code}m{text}\u001b[0m" : text;
        var name = Display.Safe(r.File);
        if (r.Ok && r.Details is { } d)
        {
            var lines = new List<string>
            {
                $"{Paint("VERIFIED".PadRight(11), "1;32", colour)}  {name}",
                $"             Sealed by     {Display.Safe(Names.Label(d.Signer, d.Organisation))}",
                $"             Issued by     {Display.Safe(Names.Label(d.IssuedBy, d.IssuerOrganisation))}",
                $"             Authority     fingerprint {d.Authority}",
                $"             Sealed on     {Time.Full(d.SealedAt)}",
                $"             Certificate   valid until {Time.Day(d.CertificateValidUntil)}"
            };
            lines.AddRange(d.Claims.Select(c => Fields.IsKnown(c.Key)
                ? $"             {c.Key.PadRight(13)} {Display.Safe(c.Value)}"
                : $"             Extra: {Display.Safe(c.Key)} {Display.Safe(c.Value)}"));
            if (d.Note.Length > 0) lines.Add($"             Note          {d.Note.Replace(") (", "; ").Trim('(', ')')}");
            return string.Join("\n", lines);
        }
        var label = r.Status == "NO_SEAL" ? "NO SEAL" : "DO NOT OPEN";
        return $"{Paint(label.PadRight(11), "1;31", colour)}  {name}\n             {Display.Safe(r.Reason)}";
    }
}
