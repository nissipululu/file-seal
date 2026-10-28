using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>The command line. Plain words for people, --json for machines. Exit codes: 0 all passed, 1 a check failed, 2 could not run.</summary>
public static class CliApp
{
    private sealed record Spec(string[] Values, string[] Flags);

    private static readonly Dictionary<string, Spec> Specs = new()
    {
        ["authority init"] = new(["--company", "--department", "--years", "--list-days", "--home"], []),
        ["authority sign"] = new(["--request", "--name", "--key", "--days", "--home"], []),
        ["authority revoke"] = new(["--name", "--serial", "--reason", "--list-days", "--home"], []),
        ["authority publish"] = new(["--list-days", "--home"], []),
        ["authority list"] = new(["--home"], []),
        ["department request"] = new(["--name", "--home"], ["--key-file"]),
        ["department install"] = new(["--cert", "--department", "--home"], []),
        ["department list"] = new(["--home"], []),
        ["department remove"] = new(["--name", "--home"], []),
        ["seal"] = new(["--made-by", "--made-for", "--what", "--edits", "--rights", "--contact", "--reference", "--department", "--store-cert", "--out", "--home"],
            ["--replace", "--force"]),
        ["check"] = new(["--trust", "--pin-root", "--home"], ["--system", "--json"]),
        ["authority share-setup"] = new(["--share", "--home"], []),
        ["authority inbox"] = new(["--home"], []),
        ["authority approve"] = new(["--name", "--key", "--days", "--home"], []),
        ["setup"] = new(["--share", "--department", "--made-by", "--made-for", "--rights", "--contact", "--edits", "--reference", "--box-folder", "--also-watch", "--notify", "--pin-root", "--home"],
            ["--key-file", "--no-autostart", "--no-start", "--no-downloads", "--trust-on-first-use"]),
        ["uninstall"] = new(["--box-folder", "--department", "--home"], []),
        ["notify-test"] = new([], []),
        ["seal-box setup"] = new(["--folder", "--department", "--made-by", "--made-for", "--rights", "--contact", "--edits", "--reference", "--share", "--notify", "--pin-root", "--home"], []),
        ["seal-box run"] = new(["--folder", "--settle", "--home"], ["--once"]),
        ["seal-box autostart"] = new(["--folder", "--home"], ["--install", "--remove"]),
        ["seal-box supervise"] = new(["--folder", "--home", "--login-item"], []),
        ["check-box setup"] = new(["--folder", "--trust", "--trust-share", "--pin-root", "--also-watch", "--notify", "--home"], ["--trust-on-first-use"]),
        ["check-box run"] = new(["--folder", "--settle", "--home"], ["--once"]),
        ["check-box autostart"] = new(["--folder", "--home"], ["--install", "--remove"]),
        ["check-box supervise"] = new(["--folder", "--home", "--login-item"], []),
    };

    /// <summary>Test only options (a pretend clock, a chosen seal date). They are refused unless the test program turns them on inside its own process, so nobody can backdate with them in real use.</summary>
    private static readonly string[] TestValues = ["--now", "--sealed-at"];

    /// <summary>Set only by the test program, in the process. Nothing outside the process, not an environment variable, can turn the test options on.</summary>
    internal static bool AllowTestOptions;
    private static bool TestOptions => AllowTestOptions;

    private sealed class Args
    {
        public List<string> Positional { get; } = [];
        public Dictionary<string, List<string>> Options { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Flags { get; } = new(StringComparer.Ordinal);

        public string? One(string name) => Options.TryGetValue(name, out var v) ? v[^1] : null;
        public List<string> Many(string name) => Options.TryGetValue(name, out var v) ? v : [];
        public string Need(string name) => One(name) ?? throw new SealException($"Please give {name}.");
        public int Number(string name, int fallback)
        {
            var text = One(name);
            if (text == null) return fallback;
            return int.TryParse(text, out var n) && n is > 0 and <= 36500 ? n : throw new SealException($"{name} must be a whole number from 1 to 36500.");
        }

        public static Args Parse(string[] argv, string command)
        {
            var spec = Specs[command];
            var a = new Args();
            var optionsEnded = false;
            for (var i = 0; i < argv.Length; i++)
            {
                var token = argv[i];
                // After a lone -- everything is a file name, even one that starts with a dash.
                if (!optionsEnded && token == "--") { optionsEnded = true; continue; }
                if (optionsEnded || token == "-" || !token.StartsWith('-')) { a.Positional.Add(token); continue; }
                if (!token.StartsWith("--", StringComparison.Ordinal))
                    throw new SealException($"I do not know the option {Display.Safe(token)}. Options start with two dashes. To name a file that starts with a dash, put -- before the file names.");
                if (spec.Flags.Contains(token)) { a.Flags.Add(token); continue; }
                if (!spec.Values.Contains(token) && !(TestOptions && TestValues.Contains(token)))
                    throw new SealException($"I do not know the option {Display.Safe(token)} for '{command}'. The options are: {string.Join(" ", spec.Values.Concat(spec.Flags))}.");
                if (i + 1 >= argv.Length || spec.Values.Contains(argv[i + 1]) || spec.Flags.Contains(argv[i + 1]))
                    throw new SealException($"{token} needs a value after it.");
                if (!a.Options.TryGetValue(token, out var list)) a.Options[token] = list = [];
                list.Add(argv[++i]);
            }
            // Only seal and check take file names. A stray word anywhere else is a mistake, and an option that was meant to count must not be lost.
            if (command is not ("seal" or "check") && a.Positional.Count > 0)
                throw new SealException($"I do not know what '{Display.Safe(a.Positional[0])}' means here. Options start with two dashes, for example --name.");
            return a;
        }
    }

    public static int Run(string[] argv, TextWriter o, TextWriter e)
    {
        try { return Dispatch(argv, o); }
        catch (SealException ex) { e.WriteLine("Error: " + Display.Safe(ex.Message)); return 2; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Whatever goes wrong, it must never look like a pass.
            e.WriteLine($"Error: something unexpected went wrong ({ex.GetType().Name}). Nothing was confirmed.");
            return 2;
        }
    }

    private const string Help = """
        Sonset file seal. Seal files with your company's own authority and check the seal before opening.

        The seamless way (a company share folder that everyone can reach):
          IT, once:        authority init --company "Example Property Group" --department "IT Department"
                           authority share-setup --share "/company/share/Sonset seal"
          Each department: setup --share "/company/share/Sonset seal" --department "Marketing Department" --made-for "Leasing team" --pin-root FINGERPRINT
                           (IT gives the whole command: share-setup prints it, with the authority's fingerprint as --pin-root.
                            Setup prints the department's own key fingerprint. The department tells IT that fingerprint, in person or by phone.
                            For a trial on your own, --trust-on-first-use can stand in for --pin-root.)
          IT, per request: authority inbox            (see who is waiting)
                           authority approve --name "Marketing Department" --key KEYFINGERPRINT
          After that nobody types anything: save files into Seal box/Drop here, open files from Check box/Verified.
          setup also watches the user's Downloads folder (leave it out with --no-downloads, add more with --also-watch FOLDER).
          A sealed file found there is checked: a genuine one stays put and you get a message, a bad one moves to Check box/Rejected.
          --notify all, problems or off sets the messages on the screen. Take it all off the computer again with: uninstall (your files stay).
          notify-test shows a test message, to see that messages reach the screen.

        Issuing department (runs the company's authority):
          authority init --company "Example Property Group" --department "IT Department"
          authority sign --request request.csr.pem --name "Marketing Department" --key KEYFINGERPRINT
               (type the department's name yourself, as you know it, so a look alike name cannot slip through)
          authority revoke --name "Marketing Department" --reason "laptop lost"
          authority publish
          authority list

        Each sealing department:
          department request --name "Marketing Department"
          department install --cert certificate.pem
          department list
          seal FILE... --made-by "J. Smith" --made-for "Leasing team" --what "Listing photo, 12 Example St"
               (optional: --edits --rights --contact --reference)

        Automatic, so nobody types anything per file:
          seal-box setup --folder "Seal box" --department "Marketing Department" --made-for "Leasing team" [--rights ...]
          seal-box run --folder "Seal box"          (save files into 'Drop here'; sealed copies appear in 'Sealed')
          check-box setup --folder "Check box" (--trust TRUSTFOLDER | --trust-share SHARE) [--pin-root SHA256 | --trust-on-first-use] [--also-watch FOLDER ...] [--notify all|problems|off]
          check-box run --folder "Check box"        (files arriving in 'Incoming' land in 'Verified' or 'Rejected')
          seal-box autostart --folder ... [--install | --remove]   (and the same for check-box: start at login, or stop and remove)
          seal-box supervise --folder ...           (runs the box and starts it again if it ever stops; the Windows login item uses this)

        Anyone who receives files:
          check FILE_OR_FOLDER... --trust TRUSTFOLDER [--pin-root SHA256FINGERPRINT]
          check FILE_OR_FOLDER... --system --pin-root SHA256FINGERPRINT   (company on Microsoft AD CS)

        Add --home FOLDER to keep everything in another folder. Add --json to check for machine output. "version" shows the version.
        """;

    /// <summary>The version this program was built as (set once, in Directory.Build.props).</summary>
    public static string Version =>
        (typeof(CliApp).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false) is [System.Reflection.AssemblyInformationalVersionAttribute v, ..]
            ? v.InformationalVersion : "unknown").Split('+')[0];

    private static int Dispatch(string[] argv, TextWriter o)
    {
        if (argv.Length == 0 || argv[0] is "help" or "--help") { o.WriteLine(Help); return 0; }
        if (argv[0] is "version" or "--version") { o.WriteLine("Sonset file seal " + Version); return 0; }
        var group = argv[0];
        var rest = argv.Skip(1).ToArray();
        if (group is "authority" or "department" or "seal-box" or "check-box")
        {
            if (rest.Length == 0) throw new SealException($"'{group}' needs a command. Run with no arguments for the list.");
            var key = $"{group} {rest[0]}";
            if (!Specs.ContainsKey(key)) throw new SealException($"I do not know '{Display.Safe(key)}'. Run with no arguments for the list.");
            return RunGroup(group, rest[0], Args.Parse(rest.Skip(1).ToArray(), key), o);
        }
        return group switch
        {
            "setup" => RunSetup(Args.Parse(rest, "setup"), o),
            "uninstall" => RunUninstall(Args.Parse(rest, "uninstall"), o),
            "notify-test" => RunNotifyTest(Args.Parse(rest, "notify-test"), o),
            "seal" => RunSeal(Args.Parse(rest, "seal"), o),
            "check" => RunCheck(Args.Parse(rest, "check"), o),
            _ => throw new SealException($"I do not know the command '{Display.Safe(group)}'. Run with no arguments for the list.")
        };
    }

    private static Home HomeOf(Args a) => new(a.One("--home") ?? Home.DefaultPath());

    private static int RunGroup(string group, string command, Args a, TextWriter o)
    {
        var home = HomeOf(a);
        var now = Time.Now();
        switch (group, command)
        {
            case ("authority", "init"):
                o.WriteLine(Authority.Init(home, a.Need("--company"), a.Need("--department"), a.Number("--years", 10), a.Number("--list-days", 30), now));
                return 0;
            case ("authority", "sign"):
            {
                var request = a.Need("--request");
                if (!File.Exists(request)) throw new SealException($"I cannot find {request}.");
                var path = Authority.SignRequest(home, File.ReadAllBytes(request), a.Need("--name"), a.Number("--days", 365), now, a.Need("--key"));
                o.WriteLine($"Signed the request. Send this certificate back to the department. It holds no secret: {path}");
                return 0;
            }
            case ("authority", "revoke"):
                o.WriteLine(Authority.Revoke(home, a.One("--name"), a.One("--serial"), a.One("--reason"), a.Number("--list-days", 30), now));
                return 0;
            case ("authority", "publish"):
            {
                var list = Authority.Publish(home, now, a.Number("--list-days", 30), null);
                o.WriteLine($"Signed a fresh list of withdrawn certificates (number {(int)list["number"]!}, {list["revoked"]!.AsArray().Count} on it). It is good until {Time.Day(Time.ParseIso((string)list["next_update"]!))}.");
                o.WriteLine($"Copy {home.Trust} to every checking computer.");
                return 0;
            }
            case ("authority", "list"):
                foreach (var line in Authority.List(home, now)) o.WriteLine(line);
                return 0;
            case ("authority", "share-setup"):
                o.WriteLine(Authority.ShareSetup(home, a.Need("--share")));
                return 0;
            case ("authority", "inbox"):
                foreach (var line in Authority.Inbox(home)) o.WriteLine(line);
                return 0;
            case ("authority", "approve"):
                o.WriteLine(Authority.Approve(home, a.Need("--name"), a.Need("--key"), a.Number("--days", 365), now));
                return 0;
            case ("department", "request"):
                o.WriteLine(Department.Request(home, a.Need("--name"), a.Flags.Contains("--key-file"), now));
                return 0;
            case ("department", "install"):
            {
                var cert = a.Need("--cert");
                if (!File.Exists(cert)) throw new SealException($"I cannot find {cert}.");
                o.WriteLine(Department.Install(home, a.One("--department"), File.ReadAllBytes(cert)));
                return 0;
            }
            case ("department", "list"):
                foreach (var line in Department.List(home)) o.WriteLine(line);
                return 0;
            case ("department", "remove"):
                Department.Remove(home, a.Need("--name"));
                o.WriteLine("Removed that department and its key from this computer.");
                return 0;
            case ("seal-box", "setup"):
            {
                var department = a.Need("--department");
                o.WriteLine(Boxes.SetupSealBox(a.Need("--folder"), new Boxes.SealDefaults(department, a.One("--made-by") ?? department,
                    a.One("--made-for"), a.One("--rights"), a.One("--contact"), a.One("--edits"), a.One("--reference"), a.One("--share"), a.One("--notify"), a.Many("--pin-root"))));
                return 0;
            }
            case ("seal-box", "run"):
            {
                var folder = a.Need("--folder");
                return RunBox(a, o, folder, (at, settle, _) => Boxes.RunSealBoxOnce(home, folder, at, settle));
            }
            case ("check-box", "setup"):
                o.WriteLine(Boxes.SetupCheckBox(a.Need("--folder"), a.One("--trust"), a.Many("--pin-root"), a.One("--trust-share"),
                    a.Options.ContainsKey("--also-watch") ? a.Many("--also-watch") : null, a.One("--notify"), a.Flags.Contains("--trust-on-first-use")));
                return 0;
            case ("check-box", "run"):
            {
                var folder = a.Need("--folder");
                // The loop looks at Incoming every pass and at the other watched folders every fifth pass, since those can be large.
                return RunBox(a, o, folder, (at, settle, count) => Boxes.RunCheckBoxOnce(home, folder, at, settle, count % 5 == 0));
            }
            case ("seal-box" or "check-box", "supervise"):
                return SuperviseBox(group, a, home, o);
            case ("seal-box" or "check-box", "autostart"):
                return Autostart(group, a, home, o);
            default:
                throw new SealException($"I do not know '{group} {command}'. Run with no arguments for the list.");
        }
    }

    private static int RunSetup(Args a, TextWriter o)
    {
        var home = HomeOf(a);
        o.WriteLine("Setting up this department:");
        o.WriteLine(SetupFlow.Run(home, new SetupFlow.Options
        {
            Share = a.Need("--share"), Department = a.Need("--department"), MadeBy = a.One("--made-by"), MadeFor = a.One("--made-for"), Rights = a.One("--rights"),
            Contact = a.One("--contact"), Edits = a.One("--edits"), Reference = a.One("--reference"), BoxFolder = a.One("--box-folder"), KeyFile = a.Flags.Contains("--key-file"),
            NoAutostart = a.Flags.Contains("--no-autostart"), NoStart = a.Flags.Contains("--no-start"), AlsoWatch = a.Many("--also-watch"),
            NoDownloads = a.Flags.Contains("--no-downloads"), Notify = a.One("--notify"), PinRoots = a.Many("--pin-root"), TrustOnFirstUse = a.Flags.Contains("--trust-on-first-use")
        }, Time.Now()));
        return 0;
    }

    private static int RunUninstall(Args a, TextWriter o)
    {
        o.WriteLine("Taking this department off this computer:");
        o.WriteLine(SetupFlow.Uninstall(HomeOf(a), a.One("--box-folder"), a.One("--department")));
        return 0;
    }

    private static int RunNotifyTest(Args a, TextWriter o)
    {
        var why = Notify.Send("Sonset seal", "This is a test message. If you can read it, messages from your seal boxes will show up like this.");
        if (why.Length == 0)
        {
            o.WriteLine("Sent a test message to the screen. If you did not see it, check that notifications are allowed (on a Mac: System Settings, Notifications, Script Editor) and that Focus is off.");
            return 0;
        }
        o.WriteLine($"No message was shown: {Display.Safe(why)}");
        return 1;
    }

    /// <summary>pass gets the time, the settle time and the number of passes so far (the check box uses it to look at its watched folders less often).</summary>
    private static int RunBox(Args a, TextWriter o, string folder, Func<DateTimeOffset, TimeSpan?, int, Boxes.BoxReport> pass)
    {
        TimeSpan? settle = null;
        if (a.One("--settle") is { } text)
            settle = TimeSpan.FromSeconds(int.TryParse(text, out var n) && n >= 0 ? n : throw new SealException("--settle must be a number of seconds."));
        if (a.Flags.Contains("--once"))
        {
            // One run, no message on the screen: the person who ran it is looking at the answer.
            var report = pass(DateTimeOffset.UtcNow, settle, 0);
            o.WriteLine($"Handled {report.Handled}, problems {report.Problems}, still being written {report.Waiting}.");
            foreach (var note in report.Notes ?? []) o.WriteLine($"  {(note.Alert ? "Look at this: " : "")}{note.Text}");
            // Anything that needs a person's eye is not a clean run: a bad file, and also a file that could not be confirmed or read.
            return report.Problems == 0 && !(report.Notes ?? []).Any(n => n.Alert) ? 0 : 1;
        }
        using var stop = new CancellationTokenSource();
        var registrations = StopOnRequest(stop);
        using var held = TakeBox(folder, o, stop.Token);
        if (held == null) return 0;
        o.WriteLine("Watching. Press Control C to stop.");
        var count = 0;
        Boxes.RunLoop(() => pass(DateTimeOffset.UtcNow, settle, count++), o, stop.Token, () => Boxes.NotifyMode(folder));
        foreach (var r in registrations) r.Dispose();
        return 0;
    }

    /// <summary>Control C, and a stop request from the system (a login item being removed, the computer shutting down), end the loop cleanly.</summary>
    private static List<IDisposable> StopOnRequest(CancellationTokenSource stop)
    {
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
        var registrations = new List<IDisposable>();
        foreach (var signal in new[] { System.Runtime.InteropServices.PosixSignal.SIGTERM, System.Runtime.InteropServices.PosixSignal.SIGHUP })
        {
            try { registrations.Add(System.Runtime.InteropServices.PosixSignalRegistration.Create(signal, ctx => { ctx.Cancel = true; stop.Cancel(); })); }
            catch (Exception e) when (e is PlatformNotSupportedException or ArgumentException) { }
        }
        return registrations;
    }

    /// <summary>
    /// Runs a box and starts it again whenever it ends (this is what the Windows login item runs). With --login-item it also ends,
    /// taking the box with it, when that login item file is gone. Only one supervisor looks after a box.
    /// </summary>
    private static int SuperviseBox(string group, Args a, Home home, TextWriter o)
    {
        var folder = Path.GetFullPath(a.Need("--folder"));
        var loginItem = a.One("--login-item");
        using var stop = new CancellationTokenSource();
        var registrations = StopOnRequest(stop);
        Func<bool> wanted = new Boxes.LoginItemWatch(loginItem).Wanted;
        using var lockHeld = Boxes.TakeSupervisorLock(folder, wanted, stop.Token, o);
        if (lockHeld == null) return 0;
        o.WriteLine("Keeping the box running, and starting it again if it ever stops. Press Control C to stop.");
        Boxes.Supervise(folder, token =>
        {
            var (exe, arguments) = Boxes.WorkerFor(group, folder, home.Root);
            return Boxes.RunProgramUntilItEnds(exe, arguments, wanted, token);
        }, wanted, stop.Token);
        foreach (var r in registrations) r.Dispose();
        return 0;
    }

    /// <summary>Only one copy of a box runs at a time. A second copy waits here and takes over if the first stops.</summary>
    private static Boxes.BoxLock? TakeBox(string folder, TextWriter o, CancellationToken stop)
    {
        var held = Boxes.BoxLock.TryTake(folder);
        if (held != null) return held;
        o.WriteLine("This box is already being watched by another copy of the program. This copy waits and takes over if that one stops. Press Control C to quit.");
        while (!stop.IsCancellationRequested)
        {
            stop.WaitHandle.WaitOne(TimeSpan.FromSeconds(10));
            if (stop.IsCancellationRequested) break;
            held = Boxes.BoxLock.TryTake(folder);
            if (held != null) return held;
        }
        return null;
    }

    /// <summary>Shows, and with --install writes, the file that makes a box start at login. It never starts anything itself.</summary>
    private static int Autostart(string group, Args a, Home home, TextWriter o)
    {
        var folder = a.Need("--folder");
        if (a.Flags.Contains("--install") && a.Flags.Contains("--remove")) throw new SealException("Use either --install or --remove, not both.");
        if (a.Flags.Contains("--remove"))
        {
            o.WriteLine(Boxes.RemoveAutostart(group, folder));
            return 0;
        }
        var item = Boxes.LoginItemFor(group, folder, home.Root);
        if (!a.Flags.Contains("--install"))
        {
            o.WriteLine($"This would be written to {item.Path}:\n\n{item.Text}\nAdd --install to write it and start the box now; it then starts at every login. Add --remove to stop it and take it away.");
            return 0;
        }
        o.WriteLine(Boxes.InstallAutostart(group, folder, home.Root, startNow: true));
        return 0;
    }

    private static int RunSeal(Args a, TextWriter o)
    {
        if (a.Positional.Count == 0) throw new SealException("Say which file to seal.");
        if (a.Positional.Count > 1 && a.One("--out") != null) throw new SealException("--out works with one file at a time.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (option, field) in new[] { ("--made-by", "Made by"), ("--made-for", "Made for"), ("--what", "What it is"),
                     ("--edits", "Edits"), ("--rights", "Rights"), ("--contact", "Contact"), ("--reference", "Reference") })
        {
            var value = a.One(option);
            if (value != null) fields[field] = value;
        }
        var home = HomeOf(a);
        var identity = a.One("--store-cert") is { } thumbprint ? StoreCertIdentity.FromStore(thumbprint) : Department.Load(home, a.One("--department"));
        var sealedAt = a.One("--sealed-at") is { } text ? Time.ParseWhen(text) : (DateTimeOffset?)null;
        var (cn, _) = Names.Parts(identity.Certificate.SubjectName);
        foreach (var file in a.Positional)
        {
            var output = Sealer.Seal(file, identity, fields, a.One("--out"), a.Flags.Contains("--replace"), a.Flags.Contains("--force"), sealedAt);
            o.WriteLine($"Sealed {Display.Safe(Path.GetFileName(file))} as {Display.Safe(Path.GetFileName(output))}. The original is untouched. Signed by {Display.Safe(cn)}.");
        }
        return 0;
    }

    private static int RunCheck(Args a, TextWriter o)
    {
        if (a.Positional.Count == 0) throw new SealException("Say which files or folders to check.");
        var now = a.One("--now") is { } text ? Time.ParseWhen(text) : Time.Now();
        var home = HomeOf(a);
        TrustPolicy trust;
        if (a.Flags.Contains("--system"))
        {
            if (a.One("--trust") != null) throw new SealException("Use either --system or --trust, not both. They mean different things.");
            trust = TrustPolicy.FromSystem(a.Many("--pin-root"));
        }
        else trust = TrustPolicy.FromFolder(a.One("--trust") ?? home.Trust, now, a.Many("--pin-root"), home.SeenLists);
        var files = Checker.Collect(a.Positional).ToList();
        if (files.Count == 0) throw new SealException("There is nothing to check.");
        var results = files.Select(f => Checker.Check(f, trust, now)).ToList();
        if (a.Flags.Contains("--json"))
        {
            var array = new JsonArray();
            foreach (var r in results)
            {
                var item = new JsonObject { ["file"] = r.File, ["status"] = r.Status, ["ok"] = r.Ok, ["reason"] = r.Reason };
                if (r.Details is { } d)
                {
                    var claims = new JsonObject();
                    foreach (var (k, v) in d.Claims) claims[k] = v;
                    item["details"] = new JsonObject
                    {
                        ["signer"] = d.Signer, ["organisation"] = d.Organisation, ["issued_by"] = d.IssuedBy, ["issuer_organisation"] = d.IssuerOrganisation,
                        ["authority_fingerprint"] = d.Authority, ["sealed_at"] = Time.Iso(d.SealedAt),
                        ["certificate_valid_until"] = Time.Iso(d.CertificateValidUntil), ["claims"] = claims, ["note"] = d.Note
                    };
                }
                array.Add(item);
            }
            o.WriteLine(array.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        }
        else
        {
            var colour = !Console.IsOutputRedirected && Environment.GetEnvironmentVariable("NO_COLOR") == null;
            foreach (var r in results) o.WriteLine(Checker.Render(r, colour));
            if (results.Count > 1) o.WriteLine($"\n{results.Count(r => r.Ok)} of {results.Count} files passed.");
        }
        return results.All(r => r.Ok) ? 0 : 1;
    }
}
