using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace SonsetSeal;

public static class Sealer
{
    /// <summary>Seal format version 2: the signature also covers which certificate signed, and the fields follow strict rules.</summary>
    public const int Version = 2;

    public static string DefaultOut(string src)
    {
        var full = Path.GetFullPath(src);
        return Path.Combine(Path.GetDirectoryName(full)!, Path.GetFileNameWithoutExtension(full) + ".sealed" + Path.GetExtension(full));
    }

    private static string Resolve(string path)
    {
        var full = Path.GetFullPath(path);
        try { return new FileInfo(full).ResolveLinkTarget(true)?.FullName ?? full; }
        catch (IOException) { return full; }
    }

    /// <summary>True when two paths name the same file, including by letter case (a Mac disk ignores case) and through links.</summary>
    private static bool SameFile(string a, string b) =>
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase)
        || string.Equals(Resolve(a), Resolve(b), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Writes a new sealed copy and never touches the original. The signature covers the file's fingerprint, the fields and
    /// the signing certificate together, so changing any of them breaks the check. <paramref name="sealedAt"/> is only for tests.
    /// </summary>
    public static string Seal(string src, SigningIdentity identity, IReadOnlyDictionary<string, string> fields, string? outPath = null,
        bool replace = false, bool force = false, DateTimeOffset? sealedAt = null)
    {
        if (!File.Exists(src)) throw new SealException($"I cannot find the file {src}.");
        var claims = Fields.Validate(fields);
        var when = sealedAt ?? Time.Now();
        var cert = identity.Certificate;
        if (sealedAt == null && !(cert.NotBefore <= when && when <= cert.NotAfter))
            throw new SealException($"The certificate of {Names.Parts(cert.SubjectName).Common} is not valid today.");

        var output = Path.GetFullPath(outPath ?? DefaultOut(src));
        if (SameFile(output, src)) throw new SealException("I never overwrite the original file. Pick a different --out.");
        if (File.Exists(output) && !force) throw new SealException($"{output} already exists. Use --force to replace it.");

        // A short, fresh, private temporary name in the output's own folder: it cannot be planted in advance, nobody else can read it while it is
        // written, and it never pushes a long file name over the limit.
        var temp = Path.Combine(Path.GetDirectoryName(output)!, "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant() + ".part");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        try
        {
            // The original is read once: the same bytes are fingerprinted and copied, so a file that changes meanwhile cannot end up with a seal for other bytes.
            using (var input = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var o = new FileStream(temp, options))
            {
                var existing = SealFormat.ReadTrailer(input);
                if (existing != null && !replace) throw new SealException("This file already carries a seal. Use --replace to strip it and seal again.");
                var bodyLength = existing?.BodyLength ?? input.Length;

                string fingerprint;
                using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    input.Seek(0, SeekOrigin.Begin);
                    var buffer = new byte[1 << 20];
                    for (var remaining = bodyLength; remaining > 0;)
                    {
                        var read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                        if (read == 0) throw new SealException("The file changed while I was sealing it.");
                        hash.AppendData(buffer, 0, read);
                        o.Write(buffer, 0, read);
                        remaining -= read;
                    }
                    fingerprint = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                }

                var claimNode = new JsonObject();
                foreach (var (key, value) in claims) claimNode[key] = value;
                var signed = new JsonObject
                {
                    ["v"] = Version, ["file_sha256"] = fingerprint, ["file_size"] = bodyLength,
                    ["sealed_at"] = Time.Iso(when), ["claims"] = claimNode, ["signer_sha256"] = Crypto.Sha256Hex(cert).ToLowerInvariant()
                };
                var canon = Canonical.Bytes(signed);
                var signature = identity.Sign(canon);
                if (!Crypto.Verify(cert, canon, signature)) throw new SealException("This department's key does not match its certificate, so I did not seal.");

                var envelope = new JsonObject
                {
                    ["signed"] = signed, ["signature"] = Convert.ToBase64String(signature), ["cert"] = cert.ExportCertificatePem()
                };
                if (identity.Chain.Count > 0)
                {
                    var chain = new JsonArray();
                    foreach (var c in identity.Chain) chain.Add(JsonValue.Create(c.ExportCertificatePem()));
                    envelope["chain"] = chain;
                }
                o.Write(SealFormat.BuildTrailer(Encoding.ASCII.GetBytes(envelope.ToJsonString())));
                o.Flush(true);
            }
            Files.CopyMode(src, temp);
            try { File.Move(temp, output, overwrite: force); }
            catch (IOException) when (File.Exists(output) && !force) { throw new SealException($"{output} already exists. Use --force to replace it."); }
        }
        catch (Exception e)
        {
            try { File.Delete(temp); } catch (IOException) { }
            if (e is PathTooLongException) throw new SealException("The file name is too long for the folder it would be sealed into.");
            throw;
        }
        return output;
    }
}
