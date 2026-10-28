using System.Diagnostics;

namespace SonsetSeal;

/// <summary>
/// Keeps one box running on Windows. A Mac login item says "start it again if it ever stops" and the Mac does that. A Windows
/// Startup file cannot say it, so the Windows login item starts a supervisor instead: it starts the box, starts it again whenever the
/// box ends for any reason (a crash, a kill, a problem the box could not survive), and goes away itself, taking the box with it,
/// when the login item file is removed. That is how "stop and remove" reaches it.
/// </summary>
public static partial class Boxes
{
    /// <summary>The wait before the first restart. It doubles each time the box falls over again soon after starting, up to the longest wait.</summary>
    internal static readonly TimeSpan RestartFirstWait = TimeSpan.FromSeconds(10);
    internal static readonly TimeSpan RestartLongestWait = TimeSpan.FromMinutes(5);
    /// <summary>A box that has run this long is working: the next restart waits only the first wait again.</summary>
    internal static readonly TimeSpan RestartStableAfter = TimeSpan.FromSeconds(60);

    /// <summary>How long a starting supervisor keeps trying for its lock before it decides another supervisor holds it (setup run again kills the old one a moment before).</summary>
    internal static TimeSpan SupervisorLockPatience = TimeSpan.FromSeconds(15);
    /// <summary>After that, a supervisor that is waiting for the lock looks again this often.</summary>
    internal static TimeSpan SupervisorLockLaterPoll = TimeSpan.FromSeconds(10);

    /// <summary>What the supervisor passes to the box on the command line. The login item and the supervisor use the same words.</summary>
    internal static string[] BoxArguments(string group, string folder, string homeRoot) => [group, "run", "--folder", folder, "--home", homeRoot];

    /// <summary>What the Windows login item runs: the supervisor, told which login item file it belongs to.</summary>
    internal static string[] SupervisorArguments(string group, string folder, string homeRoot, string loginItemPath) =>
        [group, "supervise", "--folder", folder, "--home", homeRoot, "--login-item", loginItemPath];

    /// <summary>
    /// Says whether a login item is still wanted. The file counts as gone only after it has been missing for a few seconds in a row while
    /// the folder it lives in can be reached. One failed look (a profile on the network that dropped for a moment, a scanner holding
    /// the file) must not stop a box: a box stopped by mistake stays stopped until the next sign in.
    /// </summary>
    internal sealed class LoginItemWatch(string? path, Func<DateTimeOffset>? now = null)
    {
        internal static TimeSpan Grace = TimeSpan.FromSeconds(5);
        private readonly Func<DateTimeOffset> _now = now ?? (() => DateTimeOffset.UtcNow);
        private DateTimeOffset? _missingSince;

        public bool Wanted()
        {
            if (path == null) return true;
            bool exists, folderThere;
            try
            {
                exists = File.Exists(path);
                folderThere = Directory.Exists(Path.GetDirectoryName(Path.GetFullPath(path)));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { exists = true; folderThere = true; }
            if (exists || !folderThere)
            {
                _missingSince = null;
                return true;
            }
            _missingSince ??= _now();
            return _now() - _missingSince.Value < Grace;
        }
    }

    /// <summary>
    /// Starts the box with runBox (which returns when the box ends, with its exit code) and starts it again each time it ends, until
    /// told to stop or until wanted says no. A box that keeps falling over is tried again after longer and longer waits, so a
    /// box that meets the same bad thing every time does not spin. Each restart, and a stop because the login item is gone, is
    /// written to the box's log.
    /// </summary>
    internal static void Supervise(string folder, Func<CancellationToken, int> runBox, Func<bool> wanted, CancellationToken stop,
        Func<TimeSpan, CancellationToken, bool>? pause = null, Func<DateTimeOffset>? now = null)
    {
        // The wait is taken in short slices, so a removed login item or a stop request is noticed at once, not after up to five minutes.
        pause ??= (wait, token) =>
        {
            for (var left = wait; left > TimeSpan.Zero; left -= TimeSpan.FromSeconds(1))
            {
                if (token.WaitHandle.WaitOne(left < TimeSpan.FromSeconds(1) ? left : TimeSpan.FromSeconds(1)) || !wanted()) return true;
            }
            return false;
        };
        now ??= () => DateTimeOffset.UtcNow;
        var next = RestartFirstWait;
        var gone = false;
        while (!stop.IsCancellationRequested)
        {
            if (!wanted()) { gone = true; break; }
            var started = now();
            int code;
            string? why = null;
            try { code = runBox(stop); }
            catch (Exception e) when (e is System.ComponentModel.Win32Exception or IOException or InvalidOperationException or UnauthorizedAccessException)
            {
                code = -2;
                why = $" ({Display.Safe(e.Message)})";
            }
            if (stop.IsCancellationRequested) break;
            if (!wanted()) { gone = true; break; }
            var ran = now() - started;
            if (ran >= RestartStableAfter) next = RestartFirstWait;
            SuperviseLog(folder, $"SUPERVISOR  the box ended on its own (exit code {code}{why}) after {Math.Max(0, (int)ran.TotalSeconds)} seconds. Starting it again in {(int)next.TotalSeconds} seconds.");
            if (pause(next, stop))
            {
                // Woken early: told to stop, or the login item looked gone. If it has come back, carry on as before.
                if (stop.IsCancellationRequested) break;
                continue;
            }
            next = TimeSpan.FromTicks(Math.Min(next.Ticks * 2, RestartLongestWait.Ticks));
        }
        if (gone) SuperviseLog(folder, "SUPERVISOR  the login item file is gone, so the box and its supervisor have stopped. They start again at the next sign in if the login item is put back.");
    }

    /// <summary>Tests replace the program the supervisor starts, so a test does not start a real box (on Windows that would be the test program itself).</summary>
    internal static Func<string, string, string, (string Exe, IReadOnlyList<string> Arguments)>? WorkerStarter;

    internal static (string Exe, IReadOnlyList<string> Arguments) WorkerFor(string group, string folder, string homeRoot) =>
        WorkerStarter != null ? WorkerStarter(group, folder, homeRoot)
            : (Environment.ProcessPath ?? throw new SealException("I cannot tell where this program lives."), BoxArguments(group, folder, homeRoot));

    /// <summary>
    /// Takes the lock that makes this the only supervisor of a box. Setup run again stops the old supervisor a moment before the new one starts,
    /// so a lock that looks held is tried every second for a while before it is believed. After that this copy waits and takes over if the
    /// holder stops, as a second copy of a box does. Gives up (null) when asked to stop or when the login item is gone.
    /// </summary>
    internal static BoxLock? TakeSupervisorLock(string folder, Func<bool> wanted, CancellationToken stop, TextWriter o)
    {
        var held = BoxLock.TryTake(folder, "supervisor");
        if (held != null) return held;
        o.WriteLine("This box already has a supervisor. This copy waits and takes over if that one stops. Press Control C to quit.");
        var patientUntil = DateTimeOffset.UtcNow + SupervisorLockPatience;
        while (!stop.IsCancellationRequested && wanted())
        {
            stop.WaitHandle.WaitOne(DateTimeOffset.UtcNow < patientUntil ? TimeSpan.FromSeconds(1) : SupervisorLockLaterPoll);
            if (stop.IsCancellationRequested) break;
            held = BoxLock.TryTake(folder, "supervisor");
            if (held != null) return held;
        }
        return null;
    }

    private static void SuperviseLog(string folder, string line)
    {
        try { Log(Path.GetFullPath(folder), line); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Starts a program and waits for it to end. It is ended here when stop is asked for or keepGoing says no (checked every couple of
    /// seconds). Returns its exit code, or -1 when it was ended here.
    /// </summary>
    internal static int RunProgramUntilItEnds(string exe, IEnumerable<string> arguments, Func<bool> keepGoing, CancellationToken stop)
    {
        var info = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("The box could not be started.");
        while (!process.WaitForExit(2000))
        {
            if (!stop.IsCancellationRequested && keepGoing()) continue;
            try
            {
                process.Kill(true);
                process.WaitForExit(5000);
            }
            catch (InvalidOperationException) { }
            return -1;
        }
        return process.ExitCode;
    }
}
