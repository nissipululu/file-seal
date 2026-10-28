using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>The receiver's check box: files arriving in "Incoming" are checked on their own, and the company's trust arrives from the share.</summary>
public static partial class Boxes
{
    // ---------------------------------------------------------------------------- the receiver's check box

    /// <param name="trustFolder">A trust folder on this computer. If null and a share is given, the box keeps its own copy and updates it from the share.</param>
    /// <param name="trustShare">The company share. Its Trust folder is copied in on every pass, so new withdrawals reach this computer by themselves.</param>
    /// <param name="alsoWatch">
    /// Other folders the box keeps an eye on (Downloads, a synced SharePoint folder, a shared drive). Only files that carry a seal are
    /// judged there; ordinary files are left alone. When given, this is the whole list; when null the list already saved is kept.
    /// </param>
    /// <param name="notify">"all", "problems" or "off". When null the choice already saved is kept.</param>
    /// <param name="trustOnFirstUse">With a share and no pin: trust whichever authority the share shows first, and pin that. Only for trying the tool out.</param>
    public static string SetupCheckBox(string folder, string? trustFolder, IEnumerable<string> pinRoots, string? trustShare = null,
        IEnumerable<string>? alsoWatch = null, string? notify = null, bool trustOnFirstUse = false)
    {
        var root = Path.GetFullPath(folder);
        var settingsPath = Path.Combine(root, "settings.json");
        JsonObject? before = null;
        if (File.Exists(settingsPath))
        {
            try { before = (JsonObject)JsonNode.Parse(File.ReadAllText(settingsPath))!; }
            catch (Exception e) when (e is System.Text.Json.JsonException or InvalidCastException) { before = null; }
        }
        var share = trustShare ?? (before == null ? null : Get(before, "trust_share"));
        var trust = trustFolder ?? (before == null ? null : Get(before, "trust"));
        if (trust == null && share == null) throw new SealException("Give a trust folder, or the company share it comes from.");
        var watched = new List<string>();
        var already = WatchedFolders(before);
        foreach (var raw in alsoWatch ?? already)
        {
            var full = Path.GetFullPath(raw);
            // A folder asked for now must be there. One saved earlier may be away for a while (an unplugged drive) and is kept.
            if (!already.Contains(full) && !Directory.Exists(full)) throw new SealException($"I cannot find the folder {Display.Safe(full)} to watch.");
            if (IsUnder(full, root)) throw new SealException($"The check box cannot watch its own folders ({Display.Safe(full)}).");
            if (!watched.Contains(full)) watched.Add(full);
        }
        Files.MakeSecretDir(root);
        foreach (var sub in new[] { "Incoming", "Verified", "Rejected" }) Files.MakeSecretDir(Path.Combine(root, sub));
        // Running setup again keeps the pinned authority unless new pins are given: a re run must never forget who to trust.
        var pins = new JsonArray();
        var given = pinRoots.ToList();
        if (given.Count > 0) foreach (var p in TrustPolicy.NormalizePins(given)) pins.Add(JsonValue.Create(p));
        else if (before?["pin_roots"] is JsonArray old) foreach (var p in old) pins.Add(JsonValue.Create(p!.GetValue<string>()));
        var firstUse = trustOnFirstUse || before?["trust_on_first_use"]?.GetValue<bool>() == true;
        if (share != null && pins.Count == 0 && !firstUse)
            throw new SealException("A company share needs the fingerprint of the company's authority, so that nobody who can write into the share can pose as it. " +
                "Ask the issuing department for it and give it with --pin-root, or add --trust-on-first-use to trust whichever authority the share shows first (only for trying the tool out).");
        var settings = new JsonObject { ["trust"] = Path.GetFullPath(trust ?? Path.Combine(root, "trust")), ["pin_roots"] = pins };
        if (firstUse) settings["trust_on_first_use"] = true;
        if (share != null) settings["trust_share"] = Path.GetFullPath(share);
        settings["also_watch"] = new JsonArray(watched.Select(w => (JsonNode)JsonValue.Create(w)!).ToArray());
        settings["notify"] = notify != null ? CleanNotifyMode(notify) : (before == null ? "all" : NotifyMode(root));
        Files.SaveJson(settingsPath, settings);
        ReadMe(root, "Check box\n\n" +
            "Everything that arrives goes into 'Incoming'. A few seconds later it is checked and moves.\n" +
            "'Verified' holds the files whose seal is genuine and which have not changed. Open files from there.\n" +
            "'Rejected' holds everything else, each with a note saying why. Do not open those.\n" +
            "If the check cannot run (for example the trust folder is missing) nothing moves and the reason is in log.txt.\n" +
            (watched.Count == 0 ? "" :
                "\nThe box also watches these folders:\n" + string.Join("\n", watched.Select(w => "  " + w)) + "\n" +
                "A file there that carries a seal is checked. If it is genuine it stays where it is and you get a message. " +
                "If it is not, it moves to 'Rejected' with a note, and you get a message. Files with no seal are left alone and never read past their end.\n" +
                "A file that cannot be confirmed or cannot be read stays where it is. You get one message about it. Do not open it.\n"));
        return $"Set up a check box in {root}. Put arriving files into 'Incoming' and open only what lands in 'Verified'." +
               (watched.Count == 0 ? "" : $" It also watches {string.Join(", ", watched)}.");
    }

    private static List<string> WatchedFolders(JsonObject? settings) =>
        settings?["also_watch"] is JsonArray a ? a.Select(p => p!.GetValue<string>()).ToList() : [];

    private static bool IsUnder(string path, string folder) => Files.IsUnder(path, folder);

    /// <summary>The user's own Downloads folder, where mail attachments and web downloads land. SONSETSEAL_DOWNLOADS points it elsewhere (tests do).</summary>
    public static string DownloadsFolder() =>
        Environment.GetEnvironmentVariable("SONSETSEAL_DOWNLOADS")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Task> Syncing = new();

    /// <summary>Files found in Incoming that could not be confirmed, with what they and the company's lists looked like then. They are not looked at again until one of those changes.</summary>
    private static readonly Dictionary<string, (string Sig, string Gen)> Unconfirmed = new(StringComparer.Ordinal);

    /// <summary>
    /// Copies the company's current trust folder from the share, but only what is safe to trust: the authority must be a pinned one (the first one seen
    /// is taken only when trust on first use was asked for), the list of withdrawn certificates must be signed by it and not older than the one this
    /// computer already has, and both files must be small ordinary files. A share that does not answer cannot freeze the box: the work runs on its own
    /// thread, and a pass that finds the last one still waiting skips it.
    /// </summary>
    public static string? SyncTrust(string folder)
    {
        var root = Path.GetFullPath(folder);
        if (Syncing.TryGetValue(root, out var running) && !running.IsCompleted) return null;
        var task = Task.Run(() => SyncTrustNow(root));
        Syncing[root] = task;
        try { return task.Wait(TimeSpan.FromSeconds(20)) ? task.Result : null; }
        catch (AggregateException e) { return Report(root, "unexpected", $"the company share could not be handled ({e.InnerException?.GetType().Name})"); }
    }

    /// <summary>Logs a problem with the company's trust once, and gives it back as the plain line the box shows the person.</summary>
    private static string Report(string root, string key, string problem)
    {
        if (WarnOnce($"trust|{root}|{key}")) Log(root, "TRUST NOT UPDATED  " + Display.Safe(problem));
        return problem;
    }

    private static string? SyncTrustNow(string root)
    {
        var settingsPath = Path.Combine(root, "settings.json");
        if (ReadSettings(root) is not { } settings || Get(settings, "trust_share") is not { } share) return null;
        var caSource = Path.Combine(share, "Trust", "ca.pem");
        var listSource = Path.Combine(share, "Trust", "revoked.json");
        try
        {
            // Say so: if the company's trust cannot be read, a withdrawal cannot reach this computer, and the person should be told.
            if (!File.Exists(caSource) || !File.Exists(listSource))
                return Report(root, "missing", "the company share has no trust folder (or it is not reachable), so new withdrawals cannot reach this computer");
            // Each file is read once and the bytes that were checked are the bytes that are written.
            var caBytes = Files.ReadSmall(caSource);
            var listBytes = Files.ReadSmall(listSource);
            using var authority = X509Certificate2.CreateFromPem(Encoding.ASCII.GetString(caBytes));
            var fingerprint = Crypto.Sha256Hex(authority);
            var pins = TrustPolicy.NormalizePins(settings["pin_roots"]?.AsArray().Select(p => p!.GetValue<string>()));
            var firstUse = pins.Count == 0 && settings["trust_on_first_use"]?.GetValue<bool>() == true;
            if (pins.Count == 0 && !firstUse)
                return Report(root, "no-pin", "no authority is pinned on this computer, so the share is not trusted. Run setup again with --pin-root");
            if (pins.Count > 0 && !pins.Contains(fingerprint))
                return Report(root, "wrong-authority|" + fingerprint, "the authority on the share is not the one pinned on this computer");
            var listText = Encoding.UTF8.GetString(listBytes);
            if (!RevocationList.SignedBy(listText, authority))
                return Report(root, "bad-list|" + Crypto.Sha256Hex(listBytes), "the list of withdrawn certificates on the share is not signed by the authority");
            var local = Get(settings, "trust")!;
            Directory.CreateDirectory(local);
            var localList = Path.Combine(local, "revoked.json");
            if (File.Exists(localList) && RevocationList.NumberOf(listText) is { } incoming && RevocationList.NumberOf(File.ReadAllText(localList)) is { } have && incoming < have)
                return Report(root, "older-list|" + incoming, $"the list on the share (number {incoming}) is older than the one this computer has (number {have})");
            foreach (var (bytes, to) in new[] { (caBytes, Path.Combine(local, "ca.pem")), (listBytes, localList) })
                if (!File.Exists(to) || !File.ReadAllBytes(to).AsSpan().SequenceEqual(bytes)) Files.WriteAtomic(to, bytes);
            if (firstUse)
            {
                settings["pin_roots"] = new JsonArray(JsonValue.Create(fingerprint));
                Files.SaveJson(settingsPath, settings);
                Log(root, $"AUTHORITY PINNED  fingerprint {fingerprint}  (first use, as asked)");
            }
            return null;
        }
        // Whatever is in the share, the box carries on with the trust it already has. A bad file there stops nothing here.
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return Report(root, "read|" + e.GetType().Name, $"the company share could not be read ({e.GetType().Name}: {e.Message}). Trying again every few seconds");
        }
    }

    /// <summary>
    /// One pass over "Incoming", then over the other watched folders. If the check cannot run, nothing moves.
    /// scanWatched false skips the watched folders (the loop looks at them less often than at Incoming, since they can be large).
    /// </summary>
    public static BoxReport RunCheckBoxOnce(Home home, string folder, DateTimeOffset now, TimeSpan? settle = null, bool scanWatched = true)
    {
        var root = Path.GetFullPath(folder);
        var settingsPath = Path.Combine(root, "settings.json");
        if (!File.Exists(settingsPath)) throw new SealException($"{root} is not a check box yet. Run 'check-box setup' first.");
        var shareProblem = SyncTrust(root);
        var settings = (JsonObject)JsonNode.Parse(File.ReadAllText(settingsPath))!;
        var wait = settle ?? DefaultSettle;
        var incoming = Path.Combine(root, "Incoming");
        Directory.CreateDirectory(incoming);
        RecoverWorking(root);
        var files = Files.Walk(incoming).OrderBy(f => f, StringComparer.Ordinal).Where(f => !IsTemporary(Path.GetFileName(f))).ToList();
        var watched = WatchedFolders(settings);

        // What the company's lists looked like when this pass began. Read before the trust is loaded, so a file is never remembered as judged
        // against newer lists than the ones it was actually judged with.
        var gen = TrustGeneration(Get(settings, "trust"));
        // The trust folder is read once per pass. If it cannot be used, nothing is judged anywhere.
        TrustPolicy? trust = null;
        string? trustProblem = null;
        try
        {
            var pins = settings["pin_roots"]?.AsArray().Select(p => p!.GetValue<string>()).ToList() ?? [];
            trust = TrustPolicy.FromFolder(Get(settings, "trust")!, now, pins, home.SeenLists);
        }
        catch (SealException e) { trustProblem = e.Message; }

        var notes = new List<BoxNote>();
        if (shareProblem != null && WarnOnce($"share-note|{root}|{shareProblem}"))
            notes.Add(new($"The company's trust could not be updated: {Display.Safe(shareProblem)}.", true));
        int handled = 0, problems = 0, waiting = 0;
        Status(root, trustProblem != null ? "The check cannot run, so nothing was moved. " + trustProblem
            : "Working. Files that arrive in 'Incoming' are checked within a few seconds. Open only what is in 'Verified'." +
              (watched.Count > 0 ? " Also watching " + string.Join(", ", watched) + ". Files there that carry a seal are checked; other files are left alone." : ""));

        if (files.Count > 0)
        {
            if (trust == null)
            {
                if (WarnOnce($"cannot-check|{root}|{trustProblem}"))
                {
                    Log(root, $"CANNOT CHECK  {Display.Safe(trustProblem)}  ({files.Count} files left in Incoming)");
                    notes.Add(new($"The check cannot run, so files in Incoming were not checked. {Display.Safe(trustProblem)}", true));
                }
                waiting += files.Count;
            }
            else
            {
                var present = files.ToHashSet(StringComparer.Ordinal);
                foreach (var gone in Unconfirmed.Keys.Where(k => Files.IsUnder(k, incoming) && !present.Contains(k)).ToList()) Unconfirmed.Remove(gone);
                foreach (var file in files)
                {
                    var relative = Display.Safe(Path.GetRelativePath(incoming, file));
                    var shortName = Display.Safe(Path.GetFileName(file));
                    string? held = null, heldFolder = null;
                    try
                    {
                        // The cheap questions come first, asked of the file where it lies and each with a time limit: is it still being written,
                        // does it open, does it carry a seal at all. Only a file that carries one is taken in to be checked.
                        var readiness = Probe(file, now, wait);
                        if (readiness == Readiness.Busy) { waiting++; continue; }
                        if (readiness != Readiness.Ready)
                        {
                            var why = NotOpenedBecause(readiness);
                            Reject(file, root, "Incoming", "Rejected", $"Do not open this file. {why}");
                            Log(root, $"REJECTED  {relative}  {why}");
                            notes.Add(new($"Do not open {shortName}. {why}", true));
                            problems++;
                            continue;
                        }
                        var signature = FileSig(new FileInfo(file));
                        if (Unconfirmed.TryGetValue(file, out var earlier) && earlier == (signature, gen)) { waiting++; continue; }
                        var carries = Checker.CarriesSeal(file);
                        if (carries == null)
                        {
                            Unconfirmed[file] = (signature, gen);
                            waiting++;
                            if (WarnOnce($"unreadable|{file}"))
                            {
                                Log(root, $"UNREADABLE  {relative}");
                                notes.Add(new($"I could not read {shortName}, so it was not checked. Do not open it.", true));
                            }
                            continue;
                        }
                        if (carries == false)
                        {
                            Reject(file, root, "Incoming", "Rejected", "Do not open this file. This file carries no seal.");
                            Log(root, $"REJECTED  {relative}  This file carries no seal.");
                            notes.Add(new($"Do not open {shortName}. This file carries no seal.", true));
                            problems++;
                            continue;
                        }
                        // It carries a seal. It is taken into the box's private folder by a rename, checked there, and that same file moves on,
                        // so whoever can write into Incoming cannot change it between the check and the move, and a newer file that arrives
                        // under the same name is never mistaken for it.
                        (held, heldFolder) = Take(root, file);
                        AfterTakeHook?.Invoke(file);
                        var result = Checker.Check(held, trust, now);
                        if (result.Status is "CANNOT_CONFIRM" or "UNREADABLE")
                        {
                            // The file is not at fault. It goes back, and is looked at again when it changes or the company's lists do.
                            var backAt = GiveBack(held, heldFolder, file);
                            held = null;
                            Unconfirmed[backAt] = (FileSig(new FileInfo(backAt)), gen);
                            waiting++;
                            if (WarnOnce($"unconfirmed|{file}|{result.Reason}"))
                            {
                                Log(root, $"CANNOT CONFIRM  {relative}  {Display.Safe(result.Reason)}");
                                notes.Add(new($"Cannot confirm {shortName}. {Display.Safe(result.Reason)} Do not open it until it can be checked.", true));
                            }
                            continue;
                        }
                        if (result.Ok)
                        {
                            Settle(held, heldFolder, file, root, "Verified", null);
                            held = null;
                            Log(root, $"VERIFIED  {relative}");
                            notes.Add(new($"Verified {shortName}", false));
                            handled++;
                        }
                        else
                        {
                            Settle(held, heldFolder, file, root, "Rejected", $"Do not open this file. {result.Reason}");
                            held = null;
                            Log(root, $"REJECTED  {relative}  {Display.Safe(result.Reason)}");
                            notes.Add(new($"Do not open {shortName}. {Display.Safe(result.Reason)}", true));
                            problems++;
                        }
                    }
                    // One file that cannot be moved, read or checked must never stop the others, so it is reported once and tried again.
                    catch (Exception e) when (e is not OutOfMemoryException)
                    {
                        waiting++;
                        if (WarnOnce($"stuck|{file}"))
                        {
                            Log(root, $"STUCK  {relative}  {Display.Safe(e.GetType().Name + ": " + e.Message)}");
                            notes.Add(new($"{shortName} could not be handled ({Display.Safe(e.Message)}). Do not open it.", true));
                        }
                    }
                    finally
                    {
                        // Whatever went wrong, a file that was taken in is put back, never lost.
                        if (held != null && heldFolder != null) try { GiveBack(held, heldFolder, file); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
                    }
                }
            }
        }

        if (scanWatched && watched.Count > 0)
        {
            var tally = new Tally();
            InspectWatched(root, settings, watched, now, wait, () => trust, trustProblem, tally, gen);
            handled += tally.Handled; problems += tally.Problems; waiting += tally.Waiting;
            notes.AddRange(tally.Notes);
        }
        return new BoxReport(handled, problems, waiting, notes);
    }
}
