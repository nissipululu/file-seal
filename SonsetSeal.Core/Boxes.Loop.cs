using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace SonsetSeal;

/// <summary>The loop that keeps a box running, the one message per batch, and the lock that lets only one copy of a box run.</summary>
public static partial class Boxes
{
    /// <summary>
    /// Gives the on screen message for one batch, if this box's setting says it should. Returns null when nothing was due,
    /// an empty string when the message went out, otherwise the plain reason it did not.
    /// </summary>
    public static string? Announce(BoxReport report, string mode, Func<string, string, string> send)
    {
        if (mode == "off" || report.Notes is not { Count: > 0 } notes) return null;
        var chosen = mode == "problems" ? notes.Where(n => n.Alert).ToList() : notes.ToList();
        if (chosen.Count == 0) return null;
        var (title, message) = Notify.Summary(chosen);
        return send(title, message);
    }

    /// <summary>Runs a pass every couple of seconds until asked to stop, and gives one short message per batch.</summary>
    public static void RunLoop(Func<BoxReport> pass, TextWriter o, CancellationToken stop, Func<string>? notifyMode = null,
        Func<string, string, string>? send = null, TimeSpan? interval = null)
    {
        send ??= Notify.Send;
        var complained = false;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                var report = pass();
                if (report.Handled + report.Problems > 0)
                    o.WriteLine($"{Time.Iso(Time.Now())}  handled {report.Handled}, problems {report.Problems}");
                var why = Announce(report, notifyMode?.Invoke() ?? "all", send);
                if (!string.IsNullOrEmpty(why) && !complained)
                {
                    complained = true;
                    o.WriteLine($"{Time.Iso(Time.Now())}  Could not show a message on the screen: {Display.Safe(why)}");
                }
            }
            catch (SealException e) { o.WriteLine($"{Time.Iso(Time.Now())}  {Display.Safe(e.Message)}"); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { o.WriteLine($"{Time.Iso(Time.Now())}  A file could not be reached: {Display.Safe(e.Message)}"); }
            // Whatever a received file does, the box stays up: a crash here would be restarted by the login item and meet the same file again, for ever.
            catch (Exception e) when (e is not OutOfMemoryException) { o.WriteLine($"{Time.Iso(Time.Now())}  Unexpected problem, the box carries on: {Display.Safe(e.GetType().Name + ": " + e.Message)}"); }
            stop.WaitHandle.WaitOne(interval ?? TimeSpan.FromSeconds(2));
        }
    }

    // ----------------------------------------------------------------------- one copy of a box at a time

    /// <summary>
    /// Held for as long as a box is running. A second copy of the same box (one started by hand while the login item runs, say)
    /// cannot take it, so two copies never race to move the same files. The lock goes away by itself if the program is killed.
    /// The same lock, under the name "supervisor", lets only one supervisor (see Supervise) look after a box.
    /// </summary>
    public sealed class BoxLock : IDisposable
    {
        private readonly FileStream _stream;
        private readonly string _pidPath;

        private BoxLock(FileStream stream, string pidPath) { _stream = stream; _pidPath = pidPath; }

        public static string PidFile(string folder, string kind = "box") => Path.Combine(Path.GetFullPath(folder), kind + ".pid");

        /// <summary>Null when another copy already holds this box.</summary>
        public static BoxLock? TryTake(string folder, string kind = "box")
        {
            var root = Path.GetFullPath(folder);
            Directory.CreateDirectory(root);
            FileStream stream;
            try { stream = new FileStream(Path.Combine(root, kind + ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) { return null; }
            File.WriteAllText(PidFile(root, kind), Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
            return new BoxLock(stream, PidFile(root, kind));
        }

        public void Dispose()
        {
            // The pid file goes first: once the lock is let go, another copy may take it and write its own pid file at once.
            try { File.Delete(_pidPath); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            _stream.Dispose();
        }
    }

    /// <summary>The copy of this program that a pid file names, if that really is a copy of this program. A number reused by some other program is not.</summary>
    internal static Process? ProcessOfPidFile(string pidPath)
    {
        try
        {
            if (!File.Exists(pidPath) || !int.TryParse(File.ReadAllText(pidPath).Trim(), out var pid) || pid == Environment.ProcessId) return null;
            var process = Process.GetProcessById(pid);
            var ours = Path.GetFileNameWithoutExtension(Environment.ProcessPath ?? "");
            // A process that started after the pid file was written is some other program that reused the number.
            if (!string.Equals(process.ProcessName, ours, StringComparison.OrdinalIgnoreCase) || process.StartTime.ToUniversalTime() > File.GetLastWriteTimeUtc(pidPath).AddSeconds(10))
            {
                process.Dispose();
                return null;
            }
            return process;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or System.ComponentModel.Win32Exception or NotSupportedException)
        { return null; }
    }

    private static bool StopPidFileProcess(string pidPath)
    {
        using var process = ProcessOfPidFile(pidPath);
        if (process == null) return false;
        try
        {
            process.Kill();
            process.WaitForExit(5000);
            return true;
        }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        { return false; }
    }

    /// <summary>Stops the supervisor that looks after a box and then the box itself (the supervisor first, so it cannot start the box again). True when one was stopped.</summary>
    internal static bool StopFromPidFile(string folder)
    {
        var stopped = StopPidFileProcess(BoxLock.PidFile(folder, "supervisor"));
        return StopPidFileProcess(BoxLock.PidFile(folder)) | stopped;
    }

    /// <summary>Gives a supervisor that has been told to go (its login item file is gone) a moment to end the box and itself. True when it ended.</summary>
    internal static bool WaitForSupervisorToEnd(string folder, TimeSpan patience)
    {
        using var process = ProcessOfPidFile(BoxLock.PidFile(folder, "supervisor"));
        if (process == null) return false;
        try { return process.WaitForExit((int)patience.TotalMilliseconds); }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { return false; }
    }
}
