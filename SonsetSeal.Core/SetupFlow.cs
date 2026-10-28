using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>
/// One command on a department's computer. It makes the department's key, leaves the request in the company share,
/// sets up the seal box and the check box, and starts both watching. The certificate and the company's trust folder
/// arrive by themselves through the share, and the boxes pick them up. Nobody copies a file by hand.
/// </summary>
public static class SetupFlow
{
    /// <param name="AlsoWatch">Other folders the check box keeps an eye on, besides the user's Downloads.</param>
    /// <param name="NoDownloads">Do not watch the user's Downloads folder (and stop watching it if it was).</param>
    /// <param name="Notify">"all", "problems" or "off" for both boxes. Null keeps what each box already has, or "all".</param>
    /// <param name="PinRoots">The fingerprint of the company's authority, given by the issuing department. Only an authority with this fingerprint is trusted.</param>
    /// <param name="TrustOnFirstUse">Instead of a pin: trust whichever authority the share shows now. Only for trying the tool out.</param>
    public sealed record Options
    {
        public required string Share { get; init; }
        public required string Department { get; init; }
        public string? MadeBy { get; init; }
        public string? MadeFor { get; init; }
        public string? Rights { get; init; }
        public string? Contact { get; init; }
        public string? Edits { get; init; }
        public string? Reference { get; init; }
        public string? BoxFolder { get; init; }
        public bool KeyFile { get; init; }
        public bool NoAutostart { get; init; }
        public bool NoStart { get; init; }
        public IReadOnlyList<string>? AlsoWatch { get; init; }
        public bool NoDownloads { get; init; }
        public string? Notify { get; init; }
        public IReadOnlyList<string>? PinRoots { get; init; }
        public bool TrustOnFirstUse { get; init; }
    }

    public static string DefaultBoxFolder() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Sonset");

    public static string Run(Home home, Options o, DateTimeOffset now)
    {
        var name = Names.CleanStrict(o.Department, "department name");
        var share = Path.GetFullPath(o.Share);
        if (!Directory.Exists(share))
            throw new SealException($"I cannot reach the company share {share}. Check you are connected to the company network, then run this again.");
        var notify = o.Notify == null ? null : Boxes.CleanNotifyMode(o.Notify);
        var box = Path.GetFullPath(o.BoxFolder ?? DefaultBoxFolder());
        var lines = new List<string>();

        // Who to trust is decided before anything is made. Anyone who can write into the share could put a look alike authority there.
        var pins = TrustPolicy.NormalizePins(o.PinRoots).ToList();
        // Running setup again does not ask again: the authority this computer was told to trust is kept.
        if (pins.Count == 0) pins = TrustPolicy.NormalizePins(Boxes.PinnedRoots(Path.Combine(box, "Check box"))).ToList();
        if (pins.Count == 0)
        {
            if (!o.TrustOnFirstUse)
                throw new SealException("Setup needs the fingerprint of the company's authority, so that nobody who can write into the share can pose as it. " +
                    "The issuing department gives you the whole command, with --pin-root in it. If you are only trying the tool out, add --trust-on-first-use.");
            try
            {
                using var found = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(Files.ReadSmallText(Path.Combine(share, "Trust", "ca.pem")));
                pins.Add(Crypto.Sha256Hex(found));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
            { throw new SealException("The share has no authority in it yet. The issuing department has to run 'authority share-setup' first."); }
            lines.Add($"Trusting the authority the share shows now, because you asked (--trust-on-first-use). Its fingerprint is {pins[0]}. Check it with the issuing department.");
        }
        else lines.Add($"Trusting only the company authority with fingerprint {Crypto.GroupedFingerprint(pins[0])}... (pinned).");

        if (!Department.Exists(home, name))
        {
            Department.Request(home, name, o.KeyFile, now);
            lines.Add(o.KeyFile ? "Made this department's key (kept in a key file here)." : "Made this department's key. It stays in this computer's protected store and cannot be copied off.");
        }
        else lines.Add("This department already has its key here.");

        if (!Department.HasCertificate(home, name))
        {
            lines.Add($"Tell the issuing department this key fingerprint when you ask them to approve you: {Department.RequestKeyFingerprint(home, name)}");
            Department.PublishRequest(home, name, share);
            lines.Add("Left the request in the company share. The issuing department approves it with one command; this computer then installs the certificate by itself.");
        }

        var sealBox = Path.Combine(box, "Seal box");
        var checkBox = Path.Combine(box, "Check box");
        Boxes.SetupSealBox(sealBox, new Boxes.SealDefaults(name, o.MadeBy ?? name, o.MadeFor, o.Rights, o.Contact, o.Edits, o.Reference, share, notify, pins));

        // The folders the check box watches besides Incoming: what it watched before, what was asked for now, and Downloads unless declined.
        var watch = new List<string>();
        var checkSettings = Path.Combine(checkBox, "settings.json");
        if (File.Exists(checkSettings) && JsonNode.Parse(File.ReadAllText(checkSettings)) is JsonObject previous && previous["also_watch"] is JsonArray old)
            watch.AddRange(old.Select(w => w!.GetValue<string>()));
        foreach (var extra in o.AlsoWatch ?? []) watch.Add(Path.GetFullPath(extra));
        var downloads = Path.GetFullPath(Boxes.DownloadsFolder());
        if (o.NoDownloads) watch.RemoveAll(w => w == downloads);
        else if (Directory.Exists(downloads)) watch.Add(downloads);
        watch = watch.Distinct().ToList();

        Boxes.SetupCheckBox(checkBox, null, pins, share, watch, notify);
        Boxes.SyncTrust(checkBox);
        lines.Add($"Set up the seal box ({sealBox}) and the check box ({checkBox}).");
        lines.Add(watch.Count == 0
            ? "The check box watches only its own 'Incoming' folder (no other folder was added)."
            : "The check box also watches: " + string.Join(", ", watch) + ". A file there that carries a seal is checked; files with no seal are left alone.");
        var mode = Boxes.NotifyMode(sealBox);
        lines.Add(mode switch
        {
            "off" => "Messages on the screen are off.",
            "problems" => "You get a message on the screen only when something needs a look.",
            _ => "You get one short message on the screen for each batch of files."
        });
        var (installed, installProblem) = Department.TryInstallFromShare(home, name, share, pins);
        if (installed) lines.Add("The certificate was already approved and is installed.");
        else if (installProblem != null) lines.Add("The certificate in the share was not installed. " + installProblem);

        if (o.NoAutostart) lines.Add("Start at login was not set up (you asked for that). Run 'seal-box run' and 'check-box run' yourself.");
        else
        {
            lines.Add(Boxes.InstallAutostart("seal-box", sealBox, home.Root, !o.NoStart));
            lines.Add(Boxes.InstallAutostart("check-box", checkBox, home.Root, !o.NoStart));
        }
        lines.Add("From here on: save files into 'Seal box/Drop here' to seal them, and open only files that land in 'Check box/Verified' (or that the check box says are verified in a watched folder).");
        return string.Join("\n", lines.Select(l => "  " + l));
    }

    /// <summary>
    /// Takes this department off this computer: both boxes stop and lose their login items, and the department's key leaves
    /// the computer's protected store. Every file in the box folders stays where it is.
    /// </summary>
    public static string Uninstall(Home home, string? boxFolder, string? department)
    {
        var box = Path.GetFullPath(boxFolder ?? DefaultBoxFolder());
        var sealBox = Path.Combine(box, "Seal box");
        var checkBox = Path.Combine(box, "Check box");
        var lines = new List<string>
        {
            Boxes.RemoveAutostart("seal-box", sealBox),
            Boxes.RemoveAutostart("check-box", checkBox)
        };
        // Login items made for other box folders on this same home (an older setup, a different box folder) go too.
        foreach (var (label, path) in Boxes.LoginItemsFor(home.Root))
            lines.Add(Boxes.RemoveLoginItemAt(label, path));

        if (department == null && File.Exists(Path.Combine(sealBox, "settings.json")))
        {
            try { department = (JsonNode.Parse(File.ReadAllText(Path.Combine(sealBox, "settings.json"))) as JsonObject)?["department"]?.GetValue<string>(); }
            catch (Exception e) when (e is IOException or System.Text.Json.JsonException or InvalidOperationException) { }
        }
        if (!Directory.Exists(home.Departments) || Directory.GetDirectories(home.Departments).Length == 0)
            lines.Add("No department key was found on this computer.");
        else
        {
            try
            {
                Department.Remove(home, department);
                lines.Add("Removed the department's key from this computer's protected store, and its certificate.");
            }
            catch (SealException e) { lines.Add("The department's key was not removed. " + e.Message); }
        }
        lines.Add($"Your files were not touched: everything in {box} is where you left it.");
        lines.Add($"The program's settings folder {home.Root} was kept. Delete it yourself if you want it gone as well.");
        return string.Join("\n", lines.Select(l => "  " + l));
    }
}
