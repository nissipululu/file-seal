using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SonsetSeal;

/// <summary>
/// Where the seal sits in the file: the original bytes first and never touched, then one block
/// (the signed details, the signature, the signer's certificate), then the block's length (8 bytes,
/// big endian) and a 16 byte marker. Programs stop reading at the end of the real content, so they
/// never see the block. A checker reads from the end.
/// </summary>
public static class SealFormat
{
    public static readonly byte[] Magic = "~~SONSET-SEAL~1~"u8.ToArray();
    public const int TrailerFixed = 8 + 16;
    public const int MaxPayload = 1 << 20;
    private const int Chunk = 1 << 20;

    public sealed record Trailer(long BodyLength, byte[] Payload);

    /// <summary>Null when the file has no seal. Throws DamagedSealException when the marker is there but the block does not fit.</summary>
    public static Trailer? ReadTrailer(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return ReadTrailer(fs);
    }

    /// <summary>Reads from an already open file, so a check can look at one file handle from start to finish.</summary>
    public static Trailer? ReadTrailer(FileStream fs)
    {
        var size = fs.Length;
        if (size < TrailerFixed) return null;
        fs.Seek(size - TrailerFixed, SeekOrigin.Begin);
        var tail = new byte[TrailerFixed];
        fs.ReadExactly(tail);
        if (!tail.AsSpan(8).SequenceEqual(Magic)) return null;
        var length = BinaryPrimitives.ReadUInt64BigEndian(tail);
        if (length > MaxPayload || length > (ulong)(size - TrailerFixed))
            throw new DamagedSealException("The length written into the seal does not fit the file.");
        var payload = new byte[length];
        fs.Seek(size - TrailerFixed - (long)length, SeekOrigin.Begin);
        fs.ReadExactly(payload);
        return new Trailer(size - TrailerFixed - (long)length, payload);
    }

    public static byte[] BuildTrailer(byte[] payload)
    {
        var trailer = new byte[payload.Length + TrailerFixed];
        payload.CopyTo(trailer, 0);
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(payload.Length, 8), (ulong)payload.Length);
        Magic.CopyTo(trailer, payload.Length + 8);
        return trailer;
    }

    public static string HashPrefix(string path, long length)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return HashPrefix(fs, length);
    }

    public static string HashPrefix(FileStream fs, long length)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        fs.Seek(0, SeekOrigin.Begin);
        var buffer = new byte[Chunk];
        var remaining = length;
        while (remaining > 0)
        {
            var read = fs.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read == 0) throw new DamagedSealException("The file is shorter than its seal says.");
            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
}

/// <summary>The information a company puts in a seal. Plain short text, chosen by the company.</summary>
public static class Fields
{
    public static readonly string[] Required = ["Made by", "Made for", "What it is"];
    public static readonly string[] Optional = ["Edits", "Rights", "Contact", "Reference"];
    public static IEnumerable<string> All => Required.Concat(Optional);
    private static readonly HashSet<string> Known = All.ToHashSet(StringComparer.Ordinal);

    public static bool IsKnown(string name) => Known.Contains(name);

    /// <summary>Checks what the company typed. Returns the fields in their fixed order.</summary>
    public static List<KeyValuePair<string, string>> Validate(IReadOnlyDictionary<string, string> given)
    {
        foreach (var key in given.Keys)
            if (!IsKnown(key)) throw new SealException($"'{key}' is not a seal field. The fields are: {string.Join(", ", All)}.");
        foreach (var required in Required)
            if (!given.TryGetValue(required, out var v) || string.IsNullOrWhiteSpace(v)) throw new SealException($"'{required}' is required.");
        var ordered = new List<KeyValuePair<string, string>>();
        foreach (var name in All)
        {
            if (!given.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value)) continue;
            value = value.Trim();
            if (value.Length > 300) throw new SealException($"'{name}' is longer than 300 characters.");
            // The same rule the checker applies, so the sealer can never make a seal its own checker would refuse.
            if (Display.Safe(value) != value) throw new SealException($"'{name}' cannot contain control characters or hidden characters.");
            ordered.Add(new(name, value));
        }
        return ordered;
    }

    /// <summary>
    /// The checker's own rules for the fields in a seal, the same ones the sealer applies. A department that signs
    /// with its real key still cannot put extra, missing, oversized or control character fields on the screen.
    /// Returns null when the fields are fine, otherwise the plain reason.
    /// </summary>
    public static string? StrictProblem(IReadOnlyDictionary<string, string> claims)
    {
        foreach (var key in claims.Keys)
            if (!IsKnown(key)) return $"The seal has a field called '{Display.Safe(key)}', which is not one of the seal fields.";
        foreach (var required in Required)
            if (!claims.TryGetValue(required, out var v) || string.IsNullOrWhiteSpace(v)) return $"The seal has no '{required}' field, which is required.";
        foreach (var (key, value) in claims)
        {
            if (value.Length > 300) return $"The '{key}' field is longer than 300 characters.";
            if (Display.Safe(value) != value) return $"The '{key}' field holds hidden or control characters.";
        }
        return null;
    }

    /// <summary>Known fields in their fixed order, then any others (older seals) alphabetically.</summary>
    public static IEnumerable<KeyValuePair<string, string>> InOrder(IReadOnlyDictionary<string, string> claims)
    {
        foreach (var name in All)
            if (claims.TryGetValue(name, out var v)) yield return new(name, v);
        foreach (var pair in claims.Where(p => !IsKnown(p.Key)).OrderBy(p => p.Key, StringComparer.Ordinal)) yield return pair;
    }
}
