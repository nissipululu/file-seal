using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>The check box's other watched folders (Downloads and the like): only files that carry a seal are judged there.</summary>
public static partial class Boxes
{
    // ------------------------------------------------------------------------- the other watched folders (inspect mode)

    private sealed class Tally
    {
        public int Handled, Problems, Waiting;
        public List<BoxNote> Notes { get; } = [];
    }

    /// <summary>What the box remembers about one watched file, so an unchanged file is not read again.</summary>
    private sealed record SeenFile(string Sig, string State, string Gen, string Retry);

    private static readonly TimeSpan RetryAfter = TimeSpan.FromMinutes(10);

    /// <summary>Partly downloaded and hidden files are not judged. They are looked at again when they are finished.</summary>
    private static bool IsPartial(string name) =>
        name.StartsWith('.') || name.StartsWith('~') || name.EndsWith(".part", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)
        || name.EndsWith(".download", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".opdownload", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the file was written to in the last ten minutes (or has a modified date in the future that is not simply wrong).</summary>
    private static bool StillChanging(string file, DateTimeOffset now)
    {
        try
        {
            var written = File.GetLastWriteTimeUtc(file);
            return written > now.UtcDateTime - TimeSpan.FromMinutes(10) && written <= now.UtcDateTime + TimeSpan.FromMinutes(5);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return true; }
    }

    private static string FileSig(FileInfo f) => $"{f.Length}:{f.LastWriteTimeUtc.Ticks}";

    /// <summary>Changes whenever the company's authority or its list of withdrawn certificates changes, so files judged earlier are looked at again.</summary>
    private static string TrustGeneration(string? trustFolder)
    {
        if (trustFolder == null) return "";
        try
        {
            using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
            foreach (var name in new[] { "ca.pem", "revoked.json" })
            {
                var path = Path.Combine(trustFolder, name);
                if (File.Exists(path)) hash.AppendData(File.ReadAllBytes(path));
                hash.AppendData([0]);
            }
            return Convert.ToHexString(hash.GetHashAndReset())[..16];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return ""; }
    }

    private static Dictionary<string, SeenFile> LoadSeen(string root)
    {
        var seen = new Dictionary<string, SeenFile>(StringComparer.Ordinal);
        try
        {
            var path = Path.Combine(root, "seen.json");
            if (!File.Exists(path)) return seen;
            foreach (var (key, value) in (JsonObject)JsonNode.Parse(File.ReadAllText(path))!)
                if (value is JsonObject v) seen[key] = new SeenFile(Get(v, "sig") ?? "", Get(v, "state") ?? "", Get(v, "gen") ?? "", Get(v, "retry") ?? "");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidCastException) { seen.Clear(); }
        return seen;
    }

    private static void SaveSeen(string root, Dictionary<string, SeenFile> seen)
    {
        var o = new JsonObject();
        foreach (var (key, v) in seen.OrderBy(p => p.Key, StringComparer.Ordinal))
            o[key] = new JsonObject { ["sig"] = v.Sig, ["state"] = v.State, ["gen"] = v.Gen, ["retry"] = v.Retry };
        try { Files.SaveJson(Path.Combine(root, "seen.json"), o); }   // replaced in one step
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* remembering is best effort: the worst case is a second look */ }
    }

    private static bool Due(SeenFile entry, DateTimeOffset now)
    {
        try { return entry.Retry.Length == 0 || Time.ParseIso(entry.Retry) <= now; }
        catch (FormatException) { return true; }
    }

    /// <summary>
    /// Looks at the other folders. Only a file that carries a seal is judged. Genuine: it stays where it is, with a log line and a
    /// message. Not genuine: it moves to Rejected with a note. Cannot confirm or cannot read: it is left where it is and warned
    /// about once. A file with no seal is never moved, never named in a message and not read again until it changes.
    /// </summary>
    private static void InspectWatched(string root, JsonObject settings, List<string> watched, DateTimeOffset now, TimeSpan settle,
        Func<TrustPolicy?> trust, string? trustProblem, Tally tally, string gen)
    {
        var seen = LoadSeen(root);
        var before = seen.ToDictionary(p => p.Key, p => p.Value, StringComparer.Ordinal);
        // Links are not followed, and files that a cloud folder (OneDrive, SharePoint) has not downloaded yet are skipped,
        // because opening one would make the cloud download it. They are looked at once they are on this computer.
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true, IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline
                | (FileAttributes)0x400000 /* recall on data access */ | (FileAttributes)0x40000 /* recall on open */
        };
        var present = new HashSet<string>(StringComparer.Ordinal);
        var live = new List<string>();
        foreach (var folder in watched.Where(Directory.Exists))
        {
            live.Add(folder);
            IEnumerable<string> found;
            try { found = Directory.EnumerateFiles(folder, "*", options).ToList(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            foreach (var file in found.OrderBy(f => f, StringComparer.Ordinal))
            {
                if (IsUnder(file, root)) continue;
                // A name that says "still downloading" is believed only while the file is still changing. A tampered sealed file cannot hide in
                // plain sight by being called ~Invoice.pdf or .part: once it has sat still it is looked at like any other.
                if (IsPartial(Path.GetFileName(file)) && StillChanging(file, now)) continue;
                present.Add(file);
            }
        }

        foreach (var file in present.OrderBy(f => f, StringComparer.Ordinal))
        {
            FileInfo info;
            try { info = new FileInfo(file); if (!info.Exists) continue; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            var sig = FileSig(info);
            var shown = Display.Safe(file);
            var name = Display.Safe(Path.GetFileName(file));
            seen.TryGetValue(file, out var previous);
            var changed = previous == null || previous.Sig != sig;
            if (!changed)
            {
                // Nothing to do unless the company's list moved on (a signer may have been withdrawn) or a retry is due.
                if (previous!.State == "noseal") continue;
                if (previous.State is "verified" or "unconfirmed") { if (previous.Gen == gen) continue; }
                else if (!Due(previous, now)) continue;
            }

            // A file still being written, or locked by someone else, is looked at again next time. One that will not open in time is not an ordinary file.
            var readiness = Probe(file, now, settle);
            if (readiness is Readiness.Denied or Readiness.NotAFile or Readiness.Slow)
            {
                Hold(seen, file, sig, "unreadable", now);
                if (changed || previous!.State != "unreadable") Warn(root, tally, $"I could not open {name}, so it was not checked. Do not open it.", $"UNREADABLE  {shown}");
                continue;
            }
            if (readiness == Readiness.Busy) { tally.Waiting++; continue; }

            var carries = Checker.CarriesSeal(file);
            if (carries == null)
            {
                Hold(seen, file, sig, "unreadable", now);
                if (changed || previous!.State != "unreadable") Warn(root, tally, $"I could not read {name}, so it was not checked. Do not open it.", $"UNREADABLE  {shown}");
                continue;
            }
            if (carries == false) { seen[file] = new SeenFile(sig, "noseal", "", ""); continue; }

            var policy = trust();
            if (policy == null)
            {
                if (WarnOnce($"cannot-check-watched|{root}|{trustProblem}"))
                    Warn(root, tally, $"The check cannot run, so sealed files in watched folders were not checked. {Display.Safe(trustProblem)}", $"CANNOT CHECK  {Display.Safe(trustProblem)}  (watched folders)");
                continue;
            }
            var result = Checker.Check(file, policy, now);
            switch (result.Status)
            {
                case "VERIFIED":
                    seen[file] = new SeenFile(sig, "verified", gen, "");
                    if (previous == null || previous.Sig != sig || previous.State != "verified")
                    {
                        Log(root, $"VERIFIED  {shown}  (watched folder)");
                        tally.Notes.Add(new($"Verified {name}", false));
                        tally.Handled++;
                    }
                    break;
                case "CANNOT_CONFIRM":
                    seen[file] = new SeenFile(sig, "unconfirmed", gen, "");
                    if (previous == null || previous.Sig != sig || previous.State != "unconfirmed")
                        Warn(root, tally, $"Cannot confirm {name}. {Display.Safe(result.Reason)} Do not open it until it can be checked.", $"CANNOT CONFIRM  {shown}  {Display.Safe(result.Reason)}");
                    break;
                case "UNREADABLE":
                    Hold(seen, file, sig, "unreadable", now);
                    if (previous == null || previous.Sig != sig || previous.State != "unreadable")
                        Warn(root, tally, $"I could not read {name}, so it was not checked. Do not open it.", $"UNREADABLE  {shown}");
                    break;
                case "NO_SEAL":
                    seen[file] = new SeenFile(sig, "noseal", "", "");
                    break;
                default:
                    try
                    {
                        var target = UniquePath(Path.Combine(root, "Rejected", Path.GetFileName(file)));
                        Files.Move(file, target);
                        WriteWhy(target, $"Do not open this file. {result.Reason}\nIt was found in {Display.Safe(Path.GetDirectoryName(file))} and moved here.");
                        seen.Remove(file);
                        Log(root, $"REJECTED  {shown}  {Display.Safe(result.Reason)}  (watched folder, moved to Rejected)");
                        tally.Notes.Add(new($"Do not open {name}. {Display.Safe(result.Reason)} It was moved to Rejected.", true));
                        tally.Problems++;
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    {
                        Hold(seen, file, sig, "stuck", now);
                        if (previous == null || previous.Sig != sig || previous.State != "stuck")
                            Warn(root, tally, $"Do not open {name}. {Display.Safe(result.Reason)} It could not be moved out of the way.", $"REJECTED, NOT MOVED  {shown}  {Display.Safe(result.Reason)}");
                    }
                    break;
            }
        }

        // Forget files that are gone and folders that are no longer watched. A folder that is missing right now (a drive that is not plugged in) keeps its memory.
        foreach (var key in seen.Keys.ToList())
        {
            var inLive = live.Any(w => IsUnder(key, w));
            var inWatched = watched.Any(w => IsUnder(key, w));
            if (!inWatched || (inLive && !present.Contains(key))) seen.Remove(key);
        }
        if (!seen.OrderBy(p => p.Key, StringComparer.Ordinal).SequenceEqual(before.OrderBy(p => p.Key, StringComparer.Ordinal))) SaveSeen(root, seen);
    }

    private static void Hold(Dictionary<string, SeenFile> seen, string file, string sig, string state, DateTimeOffset now) =>
        seen[file] = new SeenFile(sig, state, "", Time.Iso(now + RetryAfter));

    private static void Warn(string root, Tally tally, string message, string logLine)
    {
        Log(root, logLine);
        tally.Notes.Add(new(message, true));
    }
}
