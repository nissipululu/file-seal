using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SonsetSeal;

/// <summary>Something the person running the tool should be told about in plain words.</summary>
public class SealException(string message) : Exception(message);

/// <summary>The seal block is there but cannot be read.</summary>
public sealed class DamagedSealException(string message) : SealException(message);

public static class Time
{
    private const string IsoFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    public static DateTimeOffset Now()
    {
        var n = DateTimeOffset.UtcNow;
        return new DateTimeOffset(n.Year, n.Month, n.Day, n.Hour, n.Minute, n.Second, TimeSpan.Zero);
    }

    public static string Iso(DateTimeOffset t) => t.UtcDateTime.ToString(IsoFormat, CultureInfo.InvariantCulture);

    public static DateTimeOffset ParseIso(string s) =>
        DateTimeOffset.ParseExact(s, IsoFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    /// <summary>For the test options --now and --sealed-at: 2026-10-21 or 2026-10-21T09:00:00Z.</summary>
    public static DateTimeOffset ParseWhen(string s)
    {
        foreach (var fmt in new[] { IsoFormat, "yyyy-MM-dd" })
        {
            if (DateTimeOffset.TryParseExact(s, fmt, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)) return t;
        }
        throw new SealException($"I cannot read the date '{s}'. Use 2026-10-21 or 2026-10-21T09:00:00Z.");
    }

    /// <summary>
    /// The time zone every date a person reads is shown in: this computer's own, so an evening note never carries tomorrow's date because it showed UTC.
    /// The stamps kept inside seals, lists and log files stay UTC with a Z. Tests set another zone.
    /// </summary>
    internal static TimeZoneInfo ReadingZone = TimeZoneInfo.Local;

    public static string Day(DateTimeOffset t) =>
        TimeZoneInfo.ConvertTime(t, ReadingZone).ToString("MMM dd, yyyy", CultureInfo.InvariantCulture);

    /// <summary>Day and time of day, for example "Oct 26, 2026 8:05 PM local time".</summary>
    public static string Full(DateTimeOffset t)
    {
        var local = TimeZoneInfo.ConvertTime(t, ReadingZone);
        var hour = local.Hour % 12 == 0 ? 12 : local.Hour % 12;
        var label = ReadingZone.Id is "UTC" or "Etc/UTC" ? "UTC" : "local time";
        return $"{local.ToString("MMM dd, yyyy", CultureInfo.InvariantCulture)} {hour}:{local.ToString("mm", CultureInfo.InvariantCulture)} {(local.Hour < 12 ? "AM" : "PM")} {label}";
    }
}

public static class Names
{
    /// <summary>
    /// For names an authority puts in a certificate: letters, numbers, punctuation and single plain spaces only.
    /// No hidden, invisible or direction changing characters, no double spaces, no spaces at either end.
    /// </summary>
    private static readonly int[] InvisibleLetters = [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x2800, 0x3164, 0xFFA0];

    private static bool IsVariationSelector(int value) => value is >= 0xFE00 and <= 0xFE0F or >= 0xE0100 and <= 0xE01EF;

    public static string CleanStrict(string? text, string what)
    {
        text ??= "";
        if (text.Length is < 1 or > 64) throw new SealException($"The {what} must be 1 to 64 characters.");
        var problem = $"The {what} can only use letters, numbers, punctuation and single spaces, with no hidden or invisible characters.";
        if (text != text.Trim() || text.Contains("  ", StringComparison.Ordinal)) throw new SealException(problem);
        var marks = 0;
        var previous = ' ';
        foreach (var rune in text.EnumerateRunes())
        {
            if (rune.Value == ' ') { previous = ' '; marks = 0; continue; }
            var category = Rune.GetUnicodeCategory(rune);
            // Letters and fillers that draw nothing, and marks that have no letter to sit on or are piled up, make a name look like another name.
            if (Array.IndexOf(InvisibleLetters, rune.Value) >= 0 || IsVariationSelector(rune.Value)) throw new SealException(problem);
            var isMark = category is UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark;
            if (isMark && (previous == ' ' || ++marks > 2)) throw new SealException(problem);
            if (!isMark) marks = 0;
            previous = 'x';
            var fine = category is UnicodeCategory.UppercaseLetter or UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter
                or UnicodeCategory.ModifierLetter or UnicodeCategory.OtherLetter or UnicodeCategory.NonSpacingMark
                or UnicodeCategory.SpacingCombiningMark or UnicodeCategory.EnclosingMark or UnicodeCategory.DecimalDigitNumber
                or UnicodeCategory.LetterNumber or UnicodeCategory.OtherNumber or UnicodeCategory.ConnectorPunctuation
                or UnicodeCategory.DashPunctuation or UnicodeCategory.OpenPunctuation or UnicodeCategory.ClosePunctuation
                or UnicodeCategory.InitialQuotePunctuation or UnicodeCategory.FinalQuotePunctuation or UnicodeCategory.OtherPunctuation
                or UnicodeCategory.MathSymbol or UnicodeCategory.CurrencySymbol or UnicodeCategory.ModifierSymbol or UnicodeCategory.OtherSymbol;
            if (!fine) throw new SealException(problem);
        }
        return text;
    }

    public static string Slug(string text)
    {
        var slug = Regex.Replace(text.ToLowerInvariant(), "[^a-z0-9]+", "-").Trim('-');
        if (slug.Length == 0) throw new SealException("That name has no letters or numbers in it.");
        return slug;
    }

    public static (string? Common, string? Organisation) Parts(X500DistinguishedName dn)
    {
        string? cn = null, org = null;
        foreach (var rdn in dn.EnumerateRelativeDistinguishedNames())
        {
            if (rdn.HasMultipleElements) continue; // names like CN=Bob+OU=Sales: skip, never crash
            var oid = rdn.GetSingleElementType().Value;
            if (oid == "2.5.4.3") cn = rdn.GetSingleElementValue();
            else if (oid == "2.5.4.10") org = rdn.GetSingleElementValue();
        }
        return (cn, org);
    }

    public static X500DistinguishedName Build(string common, string? organisation)
    {
        var b = new X500DistinguishedNameBuilder();
        if (organisation != null) b.AddOrganizationName(organisation);
        b.AddCommonName(common);
        return b.Build();
    }

    public static string Label(string? common, string? organisation) =>
        organisation == null ? (common ?? "unknown") : $"{common}, {organisation}";
}

internal static class Files
{
    /// <summary>A folder only this user can open. An existing folder is tightened too, not just a new one.</summary>
    public static void MakeSecretDir(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            // A folder inside the user's own profile is private by the profile's permissions. Anywhere else it may be open to every user of the computer.
            if (!IsUnder(path, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)))
                throw new SealException($"On Windows this folder has to be inside your own user folder, so that other people who use the computer cannot open it: {Display.Safe(path)}");
            Directory.CreateDirectory(path);
            return;
        }
        const UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(path, mode);
        // A folder this user does not own, or a disk that does not take permissions, keeps what it has.
        try { File.SetUnixFileMode(path, mode); } catch (Exception e) when (e is IOException or UnauthorizedAccessException or PlatformNotSupportedException) { }
    }

    public static void WriteSecret(string path, string text)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using var stream = new FileStream(path, options);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.Write(text);
    }

    public static JsonNode LoadJson(string path, JsonNode fallback) =>
        File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path))! : fallback;

    /// <summary>Replaces a file in one step through a private temporary file, so a crash or a reader at the wrong moment never sees half a file.</summary>
    public static void WriteAtomic(string path, string text) => WriteAtomic(path, new UTF8Encoding(false).GetBytes(text));

    /// <summary>
    /// The new file takes the place of whatever is at the path, even a link planted there: the link itself is replaced, nothing it points at is written.
    /// That makes it safe for a shared folder as well.
    /// </summary>
    public static void WriteAtomic(string path, byte[] bytes)
    {
        var temp = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path))!, "." + Guid.NewGuid().ToString("N")[..12] + ".tmp");
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
            using (var stream = new FileStream(temp, options))
            {
                stream.Write(bytes);
                stream.Flush(true);
            }
            File.Move(temp, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(temp); } catch (IOException) { }
            throw;
        }
    }

    /// <summary>The largest file read from the company share. Real certificates, requests and lists are a few kilobytes.</summary>
    public const int MaxSharedFile = 1 << 20;

    /// <summary>
    /// Reads a small file that other people can write (the company share). A link, a named pipe, a file that is too big and one that does not open
    /// in time are all refused with an IOException, so nothing in a shared folder can redirect the read, hang it or fill the memory.
    /// </summary>
    public static byte[] ReadSmall(string path)
    {
        if (IsLink(path)) throw new IOException($"{Display.Safe(Path.GetFileName(path))} is a link, not a file.");
        var done = RunWithin(path, () =>
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (!fs.CanSeek || fs.Length > MaxSharedFile) throw new IOException($"{Display.Safe(Path.GetFileName(path))} is not an ordinary small file.");
            var bytes = new byte[fs.Length];
            fs.ReadExactly(bytes);
            return bytes;
        }, out var read);
        return done ? read! : throw new IOException($"{Display.Safe(Path.GetFileName(path))} did not open in time.");
    }

    public static string ReadSmallText(string path) => new UTF8Encoding(false).GetString(ReadSmall(path));

    public static void SaveJson(string path, JsonNode node) =>
        WriteAtomic(path, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");

    /// <summary>How long an open may take before it is given up on (a named pipe waits for a writer for ever, a dead network drive does not answer). Tests shorten it.</summary>
    internal static TimeSpan OpenTimeout = TimeSpan.FromSeconds(5);

    private static readonly object StuckLock = new();
    private static readonly Dictionary<string, Task> Stuck = new(StringComparer.Ordinal);

    /// <summary>
    /// Runs something that may never come back (opening a named pipe, reading from a drive that does not answer) on its own thread and waits a few seconds.
    /// False means it did not answer in time. The path is then remembered until the stuck call finally ends, so a stuck path costs one waiting thread and is
    /// not tried again meanwhile; when the call does end, the path is forgotten and tried afresh (a slow open is not a permanent verdict). Errors the work
    /// throws come out unchanged.
    /// </summary>
    internal static bool RunWithin<T>(string path, Func<T> work, out T? result)
    {
        result = default;
        lock (StuckLock)
        {
            foreach (var finished in Stuck.Where(p => p.Value.IsCompleted).Select(p => p.Key).ToList()) Stuck.Remove(finished);
            if (Stuck.ContainsKey(path) || Stuck.Count >= 256) return false;
        }
        var task = Task.Run(work);
        try
        {
            if (task.Wait(OpenTimeout)) { result = task.Result; return true; }
        }
        catch (AggregateException e) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException!).Throw(); }
        lock (StuckLock) Stuck[path] = task;
        // If the call ever ends holding something that must be closed, close it.
        task.ContinueWith(t => { if (t.Status == TaskStatus.RanToCompletion && t.Result is IDisposable d) d.Dispose(); }, TaskScheduler.Default);
        return false;
    }

    /// <summary>
    /// Moves a file to a name that does not exist yet. File.Move without overwrite makes the new name first and then removes the old one. If the old one
    /// cannot be removed (a folder this user may not change), it would leave the file under both names. This takes the new name away again, so a move
    /// that fails leaves everything exactly as it was.
    /// </summary>
    public static void Move(string from, string to)
    {
        var existed = File.Exists(to);
        try { File.Move(from, to); }
        catch
        {
            if (!existed && File.Exists(from))
                try { File.Delete(to); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            throw;
        }
    }

    /// <summary>The path with a link at its end followed to where it points (the folder itself if it is not a link). Only the last part is followed.</summary>
    public static string Resolve(string path)
    {
        var full = Path.GetFullPath(path);
        try { return new DirectoryInfo(full).ResolveLinkTarget(true)?.FullName ?? full; }
        catch (IOException) { return full; }
    }

    public static bool IsLink(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget != null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>True when the path is the folder itself or anywhere inside it.</summary>
    public static bool IsUnder(string path, string folder)
    {
        var relative = Path.GetRelativePath(Path.GetFullPath(folder), Path.GetFullPath(path));
        return relative == "." || (relative != ".." && !relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) && !Path.IsPathRooted(relative));
    }

    /// <summary>
    /// Every file under a folder. A link to a file is listed (the caller refuses it by name); a link to a folder is neither followed nor listed,
    /// because it would lead out of the folder. The default enumeration follows both kinds of link.
    /// </summary>
    public static IEnumerable<string> Walk(string root)
    {
        var options = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = FileAttributes.None };
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            var folder = pending.Pop();
            List<FileSystemInfo> entries;
            try { entries = new DirectoryInfo(folder).EnumerateFileSystemInfos("*", options).ToList(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            foreach (var entry in entries)
            {
                if (entry is DirectoryInfo) { if (entry.LinkTarget == null) pending.Push(entry.FullName); }
                else yield return entry.FullName;
            }
        }
    }

    /// <summary>Gives a copy the read, write and run bits of the original and never the special ones (setuid and the like).</summary>
    public static void CopyMode(string from, string to)
    {
        if (OperatingSystem.IsWindows()) return;
        File.SetUnixFileMode(to, File.GetUnixFileMode(from) & (UnixFileMode)0x1FF);
    }
}

internal static class Crypto
{
    public static byte[] SignEc(ECDsa key, byte[] data) =>
        key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

    public static byte[] SignRsa(RSA key, byte[] data) =>
        key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public static bool Verify(X509Certificate2 cert, byte[] data, byte[] signature)
    {
        try
        {
            // A certificate with a weak key is refused here whatever it is signed by, so a weak key can never make a seal pass.
            using var ec = cert.GetECDsaPublicKey();
            if (ec != null) return ec.KeySize >= 256 && ec.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) return rsa.KeySize >= 2048 && rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException) { }
        return false;
    }

    public static string NormSerial(string hex)
    {
        var s = BigInteger.Parse("0" + hex.Trim(), NumberStyles.HexNumber).ToString("X").TrimStart('0');
        return s.Length == 0 ? "0" : s;
    }

    public static string Sha256Hex(X509Certificate2 cert) => Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));

    public static string Sha256Hex(byte[] data) => Convert.ToHexString(SHA256.HashData(data));

    /// <summary>The first 8 bytes of a certificate's fingerprint, in groups, for a person to compare on screen.</summary>
    public static string ShortFingerprint(X509Certificate2 cert) => GroupedFingerprint(Sha256Hex(cert));

    /// <summary>The first 8 bytes of a hash as 16 hex digits in groups of four, for a person to read out or compare.</summary>
    public static string GroupedFingerprint(string hex)
    {
        hex = hex[..16].ToUpperInvariant();
        return string.Join(' ', Enumerable.Range(0, 4).Select(i => hex.Substring(i * 4, 4)));
    }

    public static string KeySha256Hex(PublicKey key) => Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
}

/// <summary>Everything printed on screen that came from a file, a certificate or a seal goes through here first.</summary>
public static class Display
{
    /// <summary>Control, invisible and direction changing characters become visible escapes like \u{1B}. Nothing can fake a line or a colour.</summary>
    public static string Safe(string? text)
    {
        if (text == null) return "";
        var sb = new StringBuilder();
        foreach (var rune in text.EnumerateRunes())
        {
            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned or UnicodeCategory.Surrogate || rune.Value == 0xFFFD)
                sb.Append("\\u{").Append(rune.Value.ToString("X", CultureInfo.InvariantCulture)).Append('}');
            else sb.Append(rune.ToString());
        }
        return sb.ToString();
    }
}

/// <summary>The exact bytes that get signed: sorted keys, no spaces, plain ASCII. A second implementation has to produce exactly these bytes to check a seal.</summary>
public static class Canonical
{
    public static string Str(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20 || c > 0x7e) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    public static string Of(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                var props = e.EnumerateObject().ToList();
                if (props.Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != props.Count)
                    throw new DamagedSealException("The seal repeats a field name.");
                return "{" + string.Join(",", props.OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => Str(p.Name) + ":" + Of(p.Value))) + "}";
            case JsonValueKind.Array: return "[" + string.Join(",", e.EnumerateArray().Select(Of)) + "]";
            case JsonValueKind.String: return Str(e.GetString()!);
            case JsonValueKind.Number: return e.GetRawText();
            case JsonValueKind.True: return "true";
            case JsonValueKind.False: return "false";
            case JsonValueKind.Null: return "null";
            default: throw new DamagedSealException("The seal holds something unexpected.");
        }
    }

    public static byte[] Bytes(JsonNode node)
    {
        using var doc = JsonDocument.Parse(node.ToJsonString());
        return Encoding.ASCII.GetBytes(Of(doc.RootElement));
    }
}
