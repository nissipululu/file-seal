using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>The department's seal box: files saved into "Drop here" are sealed on their own.</summary>
public static partial class Boxes
{
    // ------------------------------------------------------------------------------ the department's seal box

    public static string SetupSealBox(string folder, SealDefaults d)
    {
        var root = Path.GetFullPath(folder);
        // Folders only this user can open: nobody else on the computer can read what is sealed, or drop a file into the box.
        Files.MakeSecretDir(root);
        foreach (var sub in new[] { "Drop here", "Sealed", "Done", "Problems" }) Files.MakeSecretDir(Path.Combine(root, sub));
        var settings = new JsonObject { ["department"] = d.Department, ["made_by"] = d.MadeBy };
        foreach (var (key, value) in new[] { ("made_for", d.MadeFor), ("rights", d.Rights), ("contact", d.Contact), ("edits", d.Edits), ("reference", d.Reference), ("share", d.Share) })
            if (!string.IsNullOrWhiteSpace(value)) settings[key] = value;
        // Running setup again keeps the message setting and the pinned authority unless new ones are given: a re run must never forget who to trust.
        settings["notify"] = d.Notify != null ? CleanNotifyMode(d.Notify) : NotifyMode(root);
        var pins = (d.Pins ?? []).ToList();
        if (pins.Count == 0 && ReadSettings(root)?["pin_roots"] is JsonArray old) pins = old.Select(p => p!.GetValue<string>()).ToList();
        if (pins.Count > 0) settings["pin_roots"] = new JsonArray(TrustPolicy.NormalizePins(pins).Select(p => (JsonNode)JsonValue.Create(p)!).ToArray());
        Files.SaveJson(Path.Combine(root, "settings.json"), settings);
        ReadMe(root, "Seal box for " + d.Department + "\n\n" +
            "Save a file into the folder 'Drop here'. A few seconds later its sealed copy is in 'Sealed' and the original is in 'Done'.\n" +
            "To say who a file is for, put it in a folder named for them inside 'Drop here' (for example Drop here/Leasing team).\n" +
            "'What it is' is taken from the file's name. If something cannot be sealed it goes to 'Problems' with a note saying why.\n" +
            "Open status.txt to see what the box is doing. Nothing needs typing and there is no password.\n");
        return $"Set up a seal box in {root}. Save files into 'Drop here'.";
    }

    /// <summary>The box's settings file, or null when there is none or it cannot be read.</summary>
    private static JsonObject? ReadSettings(string root)
    {
        try
        {
            var path = Path.Combine(root, "settings.json");
            return File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path)) as JsonObject : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Text.Json.JsonException) { return null; }
    }

    /// <summary>The authority fingerprints a box was set up to trust (empty when none).</summary>
    public static List<string> PinnedRoots(string folder) =>
        ReadSettings(Path.GetFullPath(folder))?["pin_roots"] is JsonArray pinned ? pinned.Select(p => p!.GetValue<string>()).ToList() : [];

    private static SealDefaults LoadSealSettings(string root)
    {
        var path = Path.Combine(root, "settings.json");
        if (!File.Exists(path)) throw new SealException($"{root} is not a seal box yet. Run 'seal-box setup' first.");
        var o = (JsonObject)JsonNode.Parse(File.ReadAllText(path))!;
        var pins = o["pin_roots"] is JsonArray pinned ? pinned.Select(p => p!.GetValue<string>()).ToList() : [];
        return new SealDefaults(Get(o, "department") ?? throw new SealException("The seal box has no department."), Get(o, "made_by") ?? "", Get(o, "made_for"),
            Get(o, "rights"), Get(o, "contact"), Get(o, "edits"), Get(o, "reference"), Get(o, "share"), Pins: pins);
    }

    /// <summary>One pass over "Drop here". Returns how many were sealed, how many went to Problems, and how many are still waiting.</summary>
    public static BoxReport RunSealBoxOnce(Home home, string folder, DateTimeOffset now, TimeSpan? settle = null)
    {
        var root = Path.GetFullPath(folder);
        var defaults = LoadSealSettings(root);
        var drop = Path.Combine(root, "Drop here");
        Directory.CreateDirectory(drop);
        var notes = new List<BoxNote>();
        if (!Department.Exists(home, defaults.Department))
            throw new SealException($"This computer has no department called '{defaults.Department}'. Run 'setup' first.");
        if (!Department.HasCertificate(home, defaults.Department))
        {
            // Not approved yet. The certificate arrives through the company share, and is installed here the moment it shows up.
            var (installed, installProblem) = defaults.Share == null ? (false, null) : Department.TryInstallFromShare(home, defaults.Department, defaults.Share, defaults.Pins ?? []);
            if (!installed)
            {
                Status(root, installProblem ?? $"Waiting for the issuing department to approve {defaults.Department}. Files you save stay in 'Drop here' and are sealed as soon as it is approved.");
                if (installProblem != null && WarnOnce($"install|{root}|{installProblem}"))
                {
                    Log(root, $"CERTIFICATE NOT INSTALLED  {Display.Safe(installProblem)}");
                    notes.Add(new($"The certificate for {defaults.Department} was not installed. {Display.Safe(installProblem)}", true));
                }
                var waitingFiles = Files.Walk(drop).Count(f => !IsTemporary(Path.GetFileName(f)));
                return new BoxReport(0, 0, waitingFiles, notes);
            }
            Log(root, "CERTIFICATE INSTALLED  the issuing department approved this department");
            notes.Add(new($"{defaults.Department} was approved by the issuing department and can seal files now", false));
        }
        Status(root, $"Working. Save files into 'Drop here' and they are sealed within a few seconds. Department: {defaults.Department}.");
        var identity = Department.Load(home, defaults.Department);
        int handled = 0, problems = 0, waiting = 0;
        foreach (var file in Files.Walk(drop).OrderBy(f => f, StringComparer.Ordinal).ToList())
        {
            var name = Path.GetFileName(file);
            if (IsTemporary(name)) continue;
            var readiness = Probe(file, now, settle ?? DefaultSettle);
            if (readiness == Readiness.Busy) { waiting++; continue; }
            var relativeDir = Path.GetRelativePath(drop, Path.GetDirectoryName(file)!);
            var madeFor = relativeDir == "." ? defaults.MadeFor : relativeDir.Split(Path.DirectorySeparatorChar)[0];
            string? failure = null;
            try
            {
                if (readiness != Readiness.Ready) throw new SealException(NotOpenedBecause(readiness));
                if (string.IsNullOrWhiteSpace(madeFor)) throw new SealException("I do not know who this file is for. Put it in a folder named for them inside 'Drop here', or give the box a default.");
                var fields = new Dictionary<string, string>
                {
                    ["Made by"] = defaults.MadeBy, ["Made for"] = madeFor, ["What it is"] = Path.GetFileNameWithoutExtension(name)
                };
                foreach (var (key, value) in new[] { ("Rights", defaults.Rights), ("Contact", defaults.Contact), ("Edits", defaults.Edits), ("Reference", defaults.Reference) })
                    if (!string.IsNullOrWhiteSpace(value)) fields[key] = value;
                var outDir = Path.Combine(root, "Sealed", relativeDir == "." ? "" : relativeDir);
                Directory.CreateDirectory(outDir);
                var outPath = UniquePath(Path.Combine(outDir, Path.GetFileNameWithoutExtension(name) + ".sealed" + Path.GetExtension(name)));
                Sealer.Seal(file, identity, fields, outPath);
                MoveTo(file, root, "Drop here", "Done");
                Log(root, $"SEALED   {Display.Safe(Path.GetRelativePath(drop, file))}");
                notes.Add(new($"Sealed {Display.Safe(name)}", false));
                handled++;
                continue;
            }
            catch (SealException e) { failure = e.Message; }
            // A name too long for the Sealed folder, a full disk, a locked folder: one bad file goes to Problems like any other and never stops the box.
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { failure = "The sealed copy could not be written. " + e.Message; }

            try
            {
                Reject(file, root, "Drop here", "Problems", "This file could not be sealed. " + failure);
                Log(root, $"PROBLEM  {Display.Safe(Path.GetRelativePath(drop, file))}  {Display.Safe(failure)}");
                notes.Add(new($"Could not seal {Display.Safe(name)}. {Display.Safe(failure)}", true));
                problems++;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                waiting++;
                if (WarnOnce($"stuck|{file}"))
                {
                    Log(root, $"STUCK  {Display.Safe(Path.GetRelativePath(drop, file))}  it could not be sealed or moved out of the way: {Display.Safe(e.Message)}");
                    notes.Add(new($"{Display.Safe(name)} could not be sealed and could not be moved out of the way. {Display.Safe(failure)}", true));
                }
            }
        }
        return new BoxReport(handled, problems, waiting, notes);
    }
}
