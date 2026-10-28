using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SonsetSeal;

/// <summary>Starting a box at login: the Mac login item and the Windows startup file, installing, removing and finding them.</summary>
public static partial class Boxes
{
    // ------------------------------------------------------------------------------- starting at login

    /// <summary>Tests point this at a scratch folder so nothing lands in the real login items folder. Null means the real one.</summary>
    internal static string? LoginItemsFolderOverride;

    public sealed record LoginItem(string Label, string Path, string Text);

    private static string XmlEsc(string s) => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    /// <summary>The text that makes a Mac start a box at login and start it again if it ever stops. This never loads anything by itself.</summary>
    public static string MacLaunchAgent(string label, string exe, IEnumerable<string> arguments, string? logPath = null)
    {
        var args = string.Join("\n", new[] { exe }.Concat(arguments).Select(a => $"    <string>{XmlEsc(a)}</string>"));
        var log = logPath == null ? "" : $"\n  <key>StandardOutPath</key><string>{XmlEsc(logPath)}</string>\n  <key>StandardErrorPath</key><string>{XmlEsc(logPath)}</string>";
        return $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>Label</key><string>{XmlEsc(label)}</string>
              <key>ProgramArguments</key>
              <array>
            {args}
              </array>
              <key>RunAtLoad</key><true/>
              <key>KeepAlive</key><true/>
              <key>LimitLoadToSessionType</key><string>Aqua</string>{log}
            </dict>
            </plist>
            """ + "\n";
    }

    /// <summary>The text that makes Windows start a box at login without a console window (goes in the user's Startup folder).</summary>
    public static string WindowsStartupScript(string exe, IEnumerable<string> arguments)
    {
        static string Q(string s) => "\"\"" + s.Replace("\"", "") + "\"\"";
        var line = string.Join(" ", new[] { Q(exe) }.Concat(arguments.Select(Q)));
        return $"CreateObject(\"Wscript.Shell\").Run \"{line}\", 0, False\r\n";
    }

    private static string ShortHash(string text) =>
        Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..8].ToLowerInvariant();

    private static string Pretty(string group) => group == "seal-box" ? "The seal box" : "The check box";

    private static string LoginItemsFolder()
    {
        if (LoginItemsFolderOverride != null) return LoginItemsFolderOverride;
        if (OperatingSystem.IsMacOS()) return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "LaunchAgents");
        if (OperatingSystem.IsWindows()) return Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        throw new SealException("Starting at login is set up for Mac and Windows only.");
    }

    /// <summary>
    /// Where a box's login item lives and what it is called. The name carries a short code made from the box folder's full path,
    /// so two boxes with the same folder name in different places never share a login item.
    /// </summary>
    public static (string Label, string Path) LoginItemTarget(string group, string folder) => LoginItemTarget(group, folder, OperatingSystem.IsWindows());

    internal static (string Label, string Path) LoginItemTarget(string group, string folder, bool windows)
    {
        folder = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar);
        string slug;
        try { slug = Names.Slug(Path.GetFileName(folder)); } catch (SealException) { slug = "box"; }
        var code = ShortHash(folder);
        if (windows) return ($"Sonset {group} {slug} {code}", Path.Combine(LoginItemsFolder(), $"Sonset {group} {slug} {code}.vbs"));
        var label = $"ca.sonset.sealtool.{group}.{slug}.{code}";
        return (label, Path.Combine(LoginItemsFolder(), label + ".plist"));
    }

    /// <summary>The start at login file for one box on this computer, and where it belongs.</summary>
    public static LoginItem LoginItemFor(string group, string folder, string homeRoot) => LoginItemFor(group, folder, homeRoot, OperatingSystem.IsWindows());

    internal static LoginItem LoginItemFor(string group, string folder, string homeRoot, bool windows)
    {
        folder = Path.GetFullPath(folder);
        var exe = Environment.ProcessPath ?? throw new SealException("I cannot tell where this program lives.");
        var (label, path) = LoginItemTarget(group, folder, windows);
        // A Mac restarts a box that stops, because the login item says so. Windows has no such setting for a Startup file, so there the
        // login item starts a supervisor that does it (see Supervise).
        if (windows) return new LoginItem(label, path, WindowsStartupScript(exe, SupervisorArguments(group, folder, homeRoot, path)));
        return new LoginItem(label, path, MacLaunchAgent(label, exe, BoxArguments(group, folder, homeRoot), Path.Combine(folder, "launchd.log")));
    }

    private static string CurrentUid()
    {
        using var id = Process.Start(new ProcessStartInfo("/usr/bin/id", ["-u"]) { RedirectStandardOutput = true })!;
        var uid = id.StandardOutput.ReadToEnd().Trim();
        id.WaitForExit();
        return uid;
    }

    private static (int Code, string Text) Launchctl(params string[] args)
    {
        using var p = Process.Start(new ProcessStartInfo("/bin/launchctl", args) { RedirectStandardError = true, RedirectStandardOutput = true })!;
        var err = p.StandardError.ReadToEndAsync();
        var outText = p.StandardOutput.ReadToEndAsync();
        if (!p.WaitForExit(15000)) { p.Kill(); return (-1, "launchctl did not answer in time"); }
        return (p.ExitCode, (err.Result + outText.Result).Trim());
    }

    /// <summary>A Windows script file reads a letter such as é in a path (a user called José) right only as UTF 16 with a byte order mark. A Mac login item is plain UTF 8.</summary>
    internal static void WriteLoginItem(string path, string text, bool windows) =>
        File.WriteAllText(path, text, windows ? new UnicodeEncoding(false, true) : new UTF8Encoding(false));

    /// <summary>Makes the login item for a box and writes it where it belongs, in the form the system needs.</summary>
    internal static LoginItem WriteLoginItemFor(string group, string folder, string homeRoot, bool windows)
    {
        var item = LoginItemFor(group, folder, homeRoot, windows);
        Directory.CreateDirectory(Path.GetDirectoryName(item.Path)!);
        WriteLoginItem(item.Path, item.Text, windows);
        return item;
    }

    /// <summary>Writes the login file and starts the box now, so nobody has to log out and in. Says honestly what happened.</summary>
    public static string InstallAutostart(string group, string folder, string homeRoot, bool startNow)
    {
        var item = WriteLoginItemFor(group, folder, homeRoot, OperatingSystem.IsWindows());
        var name = Pretty(group);
        if (!startNow) return $"{name} will start at the next login.";
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                var uid = CurrentUid();
                // A copy that is already loaded is replaced, never doubled.
                (int Code, string Text) Start()
                {
                    Launchctl("bootout", $"gui/{uid}/{item.Label}");
                    return Launchctl("bootstrap", $"gui/{uid}", item.Path);
                }
                var (code, text) = Start();
                if (code != 0)
                {
                    Thread.Sleep(1500);
                    (code, text) = Start();
                }
                if (code != 0) return $"{name} will start at the next login (it could not be started right now: {Display.Safe(text)}).";
            }
            else
            {
                StopFromPidFile(folder);
                using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "wscript.exe"), [item.Path]))!;
                p.WaitForExit(5000);
            }
            return $"{name} started and will start at every login.";
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        { return $"{name} will start at the next login (it could not be started right now)."; }
    }

    private static string RemoveLoginItem(string label, string path, string name, string? folder)
    {
        var existed = File.Exists(path);
        var stopped = false;
        try
        {
            if (OperatingSystem.IsMacOS()) stopped = Launchctl("bootout", $"gui/{CurrentUid()}/{label}").Code == 0;
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or System.ComponentModel.Win32Exception) { }
        // The login item file goes first. A supervisor looking after the box ends the box and then itself a few seconds after the file is
        // gone, and never starts it again; whatever is still running after that is stopped here, the supervisor before the box.
        string? couldNotDelete = null;
        if (existed)
        {
            try { File.Delete(path); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { couldNotDelete = e.Message; }
        }
        if (folder != null)
        {
            // A supervisor whose file is still there will not end by itself, so there is nothing to wait for.
            if (couldNotDelete == null) stopped |= WaitForSupervisorToEnd(folder, TimeSpan.FromSeconds(15));
            stopped |= StopFromPidFile(folder);
        }
        var lower = name.ToLowerInvariant();
        if (couldNotDelete != null)
            return $"{name} {(stopped ? "was stopped" : "is not running")}, but its login item file could not be removed ({Display.Safe(couldNotDelete)}), so it starts again at the next login. Remove {Display.Safe(path)} yourself.";
        if (existed) return stopped ? $"Removed the login item for {lower} and stopped it." : $"Removed the login item for {lower}. It was not running.";
        return stopped ? $"{name} had no login item file, but a copy was running and has been stopped." : $"{name} had no login item.";
    }

    /// <summary>Stops a box and takes its login item away. The box's folder and every file in it stay exactly as they are.</summary>
    public static string RemoveAutostart(string group, string folder)
    {
        var (label, path) = LoginItemTarget(group, folder);
        return RemoveLoginItem(label, path, Pretty(group), folder);
    }

    /// <summary>Every login item of ours that belongs to this home folder, whichever box folder it was made for (older ones included).</summary>
    public static List<(string Label, string Path)> LoginItemsFor(string homeRoot)
    {
        var found = new List<(string, string)>();
        string dir;
        try { dir = LoginItemsFolder(); } catch (SealException) { return found; }
        if (!Directory.Exists(dir)) return found;
        var windows = OperatingSystem.IsWindows();
        foreach (var file in Directory.GetFiles(dir, windows ? "Sonset *.vbs" : "ca.sonset.sealtool.*.plist").OrderBy(f => f, StringComparer.Ordinal))
        {
            try
            {
                var text = File.ReadAllText(file);
                var mine = windows ? text.Contains("\"\"" + homeRoot + "\"\"", StringComparison.Ordinal) : text.Contains($"<string>{XmlEsc(homeRoot)}</string>", StringComparison.Ordinal);
                if (mine) found.Add((Path.GetFileNameWithoutExtension(file), file));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
        return found;
    }

    /// <summary>The box folder a login item file was made for, read from the file. Null when it cannot be told.</summary>
    internal static string? FolderOfLoginItem(string path)
    {
        try
        {
            var text = File.ReadAllText(path);
            var plist = Regex.Match(text, "<string>--folder</string>\\s*<string>([^<]*)</string>");
            var folder = plist.Success
                ? plist.Groups[1].Value.Replace("&lt;", "<").Replace("&gt;", ">").Replace("&amp;", "&")
                : Regex.Match(text, "\"\"--folder\"\"\\s+\"\"([^\"]+)\"\"") is { Success: true } script ? script.Groups[1].Value : null;
            return folder != null && Path.IsPathFullyQualified(folder) ? folder : null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>Removes one discovered login item (see LoginItemsFor), and stops the box it was made for if that box is running.</summary>
    public static string RemoveLoginItemAt(string label, string path) => RemoveLoginItem(label, path, "a box", FolderOfLoginItem(path));
}
