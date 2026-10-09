using System.Diagnostics;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal static class ClientStopTests
{
    public static void RunWindow(string[] args)
    {
        using var form = new Form { Text = "RichOnline isolated termination fixture", ShowInTaskbar = true,
            WindowState = FormWindowState.Minimized };
        if (args[0] == "ignore") form.FormClosing += (_, e) => e.Cancel = true;
        form.Shown += (_, _) => File.WriteAllText(args[1], "ready");
        Application.Run(form);
    }

    public static async Task<int> RunAsync(string outputDirectory)
    {
        var directory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(directory);
        var report = new JsonObject(); var messages = new JsonArray();
        Process? target = null; Process? other = null;
        try
        {
            var source = Environment.ProcessPath ?? throw new InvalidOperationException("Missing executable path");
            var targetPath = Path.Combine(directory, "target", "RnClient.exe");
            var otherPath = Path.Combine(directory, "other", "RnClient.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
            Directory.CreateDirectory(Path.GetDirectoryName(otherPath)!);
            File.Copy(source, targetPath, false); File.Copy(source, otherPath, false);
            Action<string, string> log = (level, text) => messages.Add(level + ": " + text);
            var selection = new ClientStopTarget(targetPath, source, null);
            var absent = await ClientStop.StopAsync(selection, log);
            Require(absent.Matched == 0, "not running");
            target = await StartAsync(targetPath, "close"); other = await StartAsync(otherPath, "ignore");
            var normal = await ClientStop.StopAsync(selection, log);
            Require(normal.Closed == 1 && normal.Forced == 0 && !other.HasExited, "normal close preserves same-name other path");
            target.Dispose(); target = await StartAsync(targetPath, "ignore");
            var forced = await ClientStop.StopAsync(selection, log);
            Require(forced.Forced == 1 && forced.Failed == 0 && !other.HasExited, "force only exact path after timeout");
            var protectedPid = await ClientStop.StopAsync(new ClientStopTarget(otherPath, source, other.Id), log);
            Require(protectedPid.Matched == 0 && !other.HasExited, "server PID exclusion");
            var refused = false;
            try { await ClientStop.StopAsync(new ClientStopTarget(otherPath, otherPath, null), log); }
            catch (ControlException e) when (e.Code == "client_is_server") { refused = true; }
            Require(refused && !other.HasExited, "server executable exclusion");
            refused = false;
            try { await ClientStop.StopAsync(new ClientStopTarget(Path.Combine(directory, "missing.exe"), source, null), log); }
            catch (ControlException e) when (e.Code == "client_path_unconfirmed") { refused = true; }
            Require(refused, "unconfirmed path rejection");
            report["ok"] = true;
            report["tests"] = new JsonArray("not_running", "normal_close", "forced_after_timeout", "same_name_other_path_preserved",
                "server_pid_excluded", "server_executable_excluded", "unconfirmed_path_rejected");
        }
        catch (Exception error) { report["ok"] = false; report["error"] = error.ToString(); }
        finally
        {
            foreach (var process in new[] { target, other })
                if (process is not null)
                {
                    if (!process.HasExited) { process.Kill(); await process.WaitForExitAsync(); }
                    process.Dispose();
                }
        }
        report["logs"] = messages;
        report["fixtureCleanup"] = "Owned fixture process handles exited/disposed; no user client targeted";
        File.WriteAllText(Path.Combine(directory, "result.json"), report.ToJsonString(JsonFormatting.Indented));
        return report["ok"]?.GetValue<bool>() == true ? 0 : 1;
    }

    private static async Task<Process> StartAsync(string executable, string mode)
    {
        var ready = Path.Combine(Path.GetDirectoryName(executable)!, Guid.NewGuid().ToString("N") + ".ready");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("--client-stop-test-window"); start.ArgumentList.Add(mode); start.ArgumentList.Add(ready);
        var child = Process.Start(start) ?? throw new InvalidOperationException("Fixture did not start");
        var watch = Stopwatch.StartNew();
        while (!File.Exists(ready))
        {
            if (child.HasExited || watch.Elapsed > TimeSpan.FromSeconds(10))
            {
                if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); }
                child.Dispose(); throw new TimeoutException("Fixture ready timeout");
            }
            await Task.Delay(25);
        }
        return child;
    }
    private static void Require(bool condition, string message)
    { if (!condition) throw new InvalidOperationException("Failed: " + message); }
}
