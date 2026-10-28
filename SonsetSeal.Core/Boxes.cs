using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>
/// The seamless part. A department keeps one folder: whatever is saved into "Drop here" is sealed on its own and the
/// sealed copy appears in "Sealed". Whoever receives files keeps another: whatever arrives in "Incoming" is checked on
/// its own and moves to "Verified" or "Rejected" with the reason. Nobody types a command, picks a field or enters a password.
/// With a company share, a department's certificate and the company's list of withdrawn certificates arrive by themselves too.
/// </summary>
public static partial class Boxes
{
    public static readonly TimeSpan DefaultSettle = TimeSpan.FromSeconds(3);

    /// <summary>One short plain line about something that happened. An alert is something the person must look at.</summary>
    public sealed record BoxNote(string Text, bool Alert);

    /// <param name="Notes">The lines for the one on screen message that goes out for this batch.</param>
    public sealed record BoxReport(int Handled, int Problems, int Waiting, IReadOnlyList<BoxNote>? Notes = null);

    public static readonly string[] NotifyModes = ["all", "problems", "off"];

    /// <summary>"all" (every batch), "problems" (only what needs a look) or "off". Set when the box is made.</summary>
    public static string CleanNotifyMode(string? mode)
    {
        mode = (mode ?? "all").Trim().ToLowerInvariant();
        if (!NotifyModes.Contains(mode)) throw new SealException("--notify must be all, problems or off.");
        return mode;
    }

    /// <summary>What this box was told to announce. A missing or unreadable settings file means "all".</summary>
    public static string NotifyMode(string folder)
    {
        try
        {
            var path = Path.Combine(Path.GetFullPath(folder), "settings.json");
            if (!File.Exists(path)) return "all";
            var o = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
            return NotifyModes.Contains(Get(o, "notify") ?? "all") ? Get(o, "notify") ?? "all" : "all";
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidCastException) { return "all"; }
    }

    private static readonly object WarnLock = new();
    private static readonly HashSet<string> Warned = [];

    /// <summary>True the first time it is asked about a message, so a standing problem is logged and announced once, not every few seconds.</summary>
    private static bool WarnOnce(string key)
    {
        lock (WarnLock) return Warned.Add(key);
    }

    public sealed record SealDefaults(string Department, string MadeBy, string? MadeFor, string? Rights, string? Contact, string? Edits, string? Reference, string? Share = null, string? Notify = null, IReadOnlyList<string>? Pins = null);

    private static bool IsTemporary(string name) =>
        name.StartsWith('.') || name.StartsWith('~') || name.EndsWith(".part", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith(".why.txt", StringComparison.OrdinalIgnoreCase) || name.Equals("README.txt", StringComparison.OrdinalIgnoreCase)
        || name.Equals("status.txt", StringComparison.OrdinalIgnoreCase) || name.Equals("log.txt", StringComparison.OrdinalIgnoreCase);

    private enum Readiness { Ready, Busy, Denied, NotAFile, Slow }

    /// <summary>
    /// A file is ready once it has sat still for a few seconds and nothing else is writing to it. Tells "someone is still writing it" (look again soon)
    /// from "this user may not read it", from "it is a link" and from "it did not open in time": a named pipe waits for a writer for ever, and a drive
    /// that is not answering is no different, so an open is given up after a few seconds (see Files.RunWithin).
    /// A modified date far in the future does not keep a file waiting for ever.
    /// </summary>
    private static Readiness Probe(string file, DateTimeOffset now, TimeSpan settle)
    {
        if (Files.IsLink(file)) return Readiness.NotAFile;
        try
        {
            var written = File.GetLastWriteTimeUtc(file);
            if (written > now.UtcDateTime - settle && written <= now.UtcDateTime + TimeSpan.FromMinutes(5)) return Readiness.Busy;
            return Files.RunWithin(file, () => { using var probe = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None); return true; }, out _)
                ? Readiness.Ready : Readiness.Slow;
        }
        catch (UnauthorizedAccessException) { return Readiness.Denied; }
        catch (IOException) { return Readiness.Busy; }
    }

    /// <summary>The plain reason a file in Incoming or Drop here is not opened, for the readiness answers that are not "ready" or "busy".</summary>
    private static string NotOpenedBecause(Readiness readiness) => readiness switch
    {
        Readiness.Denied => "This computer is not allowed to read the file.",
        Readiness.NotAFile => "It is a link, not the file itself, so it was not opened.",
        _ => "It did not open in time. It may be a named pipe, or a file on a drive that is not answering. Put it back to try again."
    };

    private static string UniquePath(string wanted)
    {
        if (!File.Exists(wanted)) return wanted;
        var dir = Path.GetDirectoryName(wanted)!;
        var stem = Path.GetFileNameWithoutExtension(wanted);
        var ext = Path.GetExtension(wanted);
        for (var i = 2; ; i++)
        {
            var candidate = Path.Combine(dir, $"{stem} ({i}){ext}");
            if (!File.Exists(candidate)) return candidate;
        }
    }

    private static void MoveTo(string file, string root, string fromSub, string toSub)
    {
        var relative = Path.GetRelativePath(Path.Combine(root, fromSub), file);
        var target = UniquePath(Path.Combine(root, toSub, relative));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        Files.Move(file, target);
    }

    /// <summary>Tests only: runs right after a file has been taken out of Incoming to be checked. Lets a test put something else where it was.</summary>
    internal static Action<string>? AfterTakeHook;

    /// <summary>
    /// Takes a file that arrived out of Incoming by renaming it into a private folder of the box (readable by this user only). A rename is instant
    /// however big the file is, keeps its dates and download marks, does not follow a link, and takes exactly the file that is there. From then on nobody
    /// who can only write into Incoming can reach it, so the file that is checked is the file that is kept. The name is kept, in a folder of its own.
    /// </summary>
    private static (string Held, string Folder) Take(string root, string file)
    {
        var parent = Path.Combine(root, ".working");
        Files.MakeSecretDir(parent);
        var folder = Path.Combine(parent, Guid.NewGuid().ToString("N")[..12]);
        Files.MakeSecretDir(folder);
        var held = Path.Combine(folder, Path.GetFileName(file));
        try { Files.Move(file, held); }
        catch { try { Directory.Delete(folder); } catch (IOException) { } throw; }
        return (held, folder);
    }

    /// <summary>Puts a taken file back where it came from (or beside it, if something took its place), so it is looked at again later.</summary>
    private static string GiveBack(string held, string folder, string original)
    {
        var target = File.Exists(original) ? UniquePath(original) : original;
        Files.Move(held, target);
        try { Directory.Delete(folder); } catch (IOException) { }
        return target;
    }

    /// <summary>Anything left in the private folder is from a pass that was cut short. It goes back to Incoming, never lost.</summary>
    private static void RecoverWorking(string root)
    {
        var parent = Path.Combine(root, ".working");
        if (!Directory.Exists(parent)) return;
        foreach (var folder in Directory.EnumerateDirectories(parent))
        {
            try
            {
                foreach (var left in Directory.EnumerateFiles(folder))
                    Files.Move(left, UniquePath(Path.Combine(root, "Incoming", Path.GetFileName(left))));
                Directory.Delete(folder);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* tried again next pass */ }
        }
    }

    /// <summary>Moves the file that was checked, still in the private folder, into Verified or Rejected under the name it arrived with.</summary>
    private static void Settle(string held, string folder, string original, string root, string toSub, string? why)
    {
        var relative = Path.GetRelativePath(Path.Combine(root, "Incoming"), original);
        var target = UniquePath(Path.Combine(root, toSub, relative));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        Files.Move(held, target);
        try { Directory.Delete(folder); } catch (IOException) { }
        if (why != null) WriteWhy(target, why);
    }

    private static void Reject(string file, string root, string fromSub, string toSub, string reason)
    {
        var relative = Path.GetRelativePath(Path.Combine(root, fromSub), file);
        var target = UniquePath(Path.Combine(root, toSub, relative));
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        Files.Move(file, target);
        WriteWhy(target, reason);
    }

    /// <summary>
    /// Writes the note that sits beside a file that was moved aside. A file name that already uses nearly all the room a name may have gets a note with
    /// a shortened name, so the note can always be written, and the full name is put inside it.
    /// </summary>
    private static void WriteWhy(string target, string reason)
    {
        var name = Path.GetFileName(target);
        var stem = name;
        while (Encoding.UTF8.GetByteCount(stem + ".why.txt") > 240) stem = stem[..^1];
        var shortened = stem != name;
        var note = Path.Combine(Path.GetDirectoryName(target)!, shortened ? stem + "~.why.txt" : name + ".why.txt");
        File.WriteAllText(note, (shortened ? $"About the file {Display.Safe(name)}\n" : "") + reason + "\n", new UTF8Encoding(false));
    }

    private static void Log(string root, string line) =>
        File.AppendAllText(Path.Combine(root, "log.txt"), $"{Time.Iso(Time.Now())}  {line}\n", new UTF8Encoding(false));

    private static void ReadMe(string root, string text) => File.WriteAllText(Path.Combine(root, "README.txt"), text, new UTF8Encoding(false));

    /// <summary>One plain line anyone can open to see what the box is doing. Only rewritten when it changes.</summary>
    private static void Status(string root, string text)
    {
        var path = Path.Combine(root, "status.txt");
        text += "\n";
        try { if (File.Exists(path) && File.ReadAllText(path) == text) return; File.WriteAllText(path, text, new UTF8Encoding(false)); }
        catch (IOException) { }
    }

    private static string? Get(JsonObject o, string key) => o[key]?.GetValue<string>();
}
