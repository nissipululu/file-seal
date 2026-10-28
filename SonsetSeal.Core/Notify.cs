using System.ComponentModel;
using System.Diagnostics;

namespace SonsetSeal;

/// <summary>A short message on the screen when something happened, so nobody has to open a folder to find out.</summary>
public static class Notify
{
    /// <summary>Tests and quiet machines set SONSETSEAL_NOTIFY=off.</summary>
    public static bool Enabled => Environment.GetEnvironmentVariable("SONSETSEAL_NOTIFY") != "off";

    private static string Clean(string text)
    {
        var safe = Display.Safe(text).Replace("\\u{A}", " ").Replace("\\u{D}", " ");
        return safe.Length > 220 ? safe[..217] + "..." : safe;
    }

    /// <summary>One message for a whole batch: the lines that need a look come first, then the first two lines in all, and a count of the rest.</summary>
    public static (string Title, string Message) Summary(IReadOnlyList<Boxes.BoxNote> notes)
    {
        var ordered = notes.OrderByDescending(n => n.Alert).ToList();
        var shown = string.Join(" ", ordered.Take(2).Select(n => n.Text.TrimEnd('.') + "."));
        if (ordered.Count > 2) shown += $" And {ordered.Count - 2} more.";
        return (ordered.Any(n => n.Alert) ? "Sonset seal: look at this" : "Sonset seal", shown);
    }

    /// <summary>Tests only: when set, messages go here instead of to the screen, after they have been cleaned.</summary>
    internal static Action<string, string>? Sink;

    /// <summary>The PowerShell script is fixed text. The title and message travel in the environment of the child process and are never part of the code,
    /// because a file name can hold quote marks (PowerShell treats the curly ones as quotes too) and would otherwise run as a command.</summary>
    internal const string BalloonScript =
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $n = New-Object System.Windows.Forms.NotifyIcon; " +
        "$n.Icon = [System.Drawing.SystemIcons]::Information; $n.Visible = $true; " +
        "$n.ShowBalloonTip(8000, $env:SONSETSEAL_TITLE, $env:SONSETSEAL_MESSAGE, 'Info'); Start-Sleep -Seconds 9; $n.Dispose()";

    internal static ProcessStartInfo WindowsBalloon(string title, string message)
    {
        // The full path, so a program of the same name in the current folder is never picked.
        var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var psi = new ProcessStartInfo(powershell, ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", BalloonScript]) { CreateNoWindow = true };
        psi.Environment["SONSETSEAL_TITLE"] = title;
        psi.Environment["SONSETSEAL_MESSAGE"] = message;
        return psi;
    }

    /// <summary>Returns an empty string when the message was sent, otherwise a plain reason it was not.</summary>
    public static string Send(string title, string message)
    {
        title = Clean(title);
        message = Clean(message);
        if (Sink != null) { Sink(title, message); return ""; }
        if (!Enabled) return "notifications are switched off on this computer (SONSETSEAL_NOTIFY is off)";
        try
        {
            if (OperatingSystem.IsMacOS())
            {
                static string Q(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
                using var p = Process.Start(new ProcessStartInfo("/usr/bin/osascript", ["-e", $"display notification {Q(message)} with title {Q(title)}"])
                { RedirectStandardError = true, RedirectStandardOutput = true })!;
                if (!p.WaitForExit(10000)) { p.Kill(); return "the Mac did not answer in time"; }
                return p.ExitCode == 0 ? "" : p.StandardError.ReadToEnd().Trim();
            }
            if (OperatingSystem.IsWindows())
            {
                // A balloon tip through PowerShell. Not tried on Windows yet.
                var psi = WindowsBalloon(title, message);
                Process.Start(psi);
                return "";
            }
        }
        catch (Exception e) when (e is IOException or InvalidOperationException or Win32Exception) { return e.Message; }
        return "notifications are set up for Mac and Windows only";
    }
}
