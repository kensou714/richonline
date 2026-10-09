using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal static class StartupTests
{
    public static async Task<int> RunAsync(string oldServer, string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        var results = new JsonArray();
        var testDirectory = Path.Combine(outputDirectory, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
        var config = Path.Combine(testDirectory, "RichOnline.Admin.launch.json");
        void Record(string name, bool passed, string detail = "") => results.Add(new JsonObject
        { ["name"] = name, ["passed"] = passed, ["detail"] = detail });
        try
        {
            var defaults = AdminLaunchSettings.Load(testDirectory, []);
            Record("missing_config_defaults", defaults.Server == Path.Combine(testDirectory, "server", "RichOnline.Server.exe"));
            Record("default_does_not_start_server", !defaults.StartServer);
            Record("explicit_start_server", AdminLaunchSettings.Load(testDirectory, ["--start-server"]).StartServer);
            foreach (var arguments in new[] { new[] { "--start-server", "true" }, new[] { "--start-server=false" },
                new[] { "--start-server", "--start-server" }, new[] { "--unknown", "value" }, new[] { "--server" } })
            {
                try { AdminLaunchSettings.Load(testDirectory, arguments); Record("reject_" + string.Join('_', arguments), false); }
                catch (ArgumentException) { Record("reject_" + string.Join('_', arguments), true); }
            }
            File.WriteAllText(config, "{\"server\":\"server/new.exe\",\"data-dir\":\"data\",\"client\":\"client/RnClient.exe\",\"client-config\":\"client/local.kpd\",\"client-profile\":\"original\"}");
            var settings = AdminLaunchSettings.Load(testDirectory, []);
            Record("relative_paths_and_profile", settings.Server == Path.GetFullPath("server/new.exe", testDirectory)
                && settings.DataDirectory == Path.GetFullPath("data", testDirectory)
                && settings.Client == Path.GetFullPath("client/RnClient.exe", testDirectory)
                && settings.ClientConfig == Path.GetFullPath("client/local.kpd", testDirectory)
                && settings.Profile == ClientProfile.Original);
            var overridePath = Path.Combine(testDirectory, "override.exe");
            settings = AdminLaunchSettings.Load(testDirectory, ["--server", overridePath, "--client-profile", "richonline"]);
            Record("cli_overrides_sidecar", settings.Server == Path.GetFullPath(overridePath) && settings.Profile == ClientProfile.Richonline);
            settings = AdminLaunchSettings.Load(testDirectory, ["--start-server", "--server", overridePath, "--client-profile", "richonline"]);
            Record("start_server_preserves_cli_overrides", settings.StartServer && settings.Server == Path.GetFullPath(overridePath)
                && settings.Profile == ClientProfile.Richonline);
            foreach (var (name, content) in new[] { ("malformed", "{"), ("unknown_field", "{\"wrong\":\"value\"}"),
                ("duplicate_field", "{\"server\":\"a\",\"server\":\"b\"}"), ("empty_field", "{\"server\":\"\"}"),
                ("invalid_profile", "{\"client-profile\":\"bad\"}") })
            {
                File.WriteAllText(config, content);
                try { AdminLaunchSettings.Load(testDirectory, []); Record(name, false); }
                catch (Exception error) when (error is InvalidDataException or ArgumentException or System.Text.Json.JsonException or ControlException)
                { Record(name, true); }
            }
            using var server = new ServerProcess();
            var logs = new List<string>();
            server.Log += (_, line) => { lock (logs) logs.Add(line); };
            try
            {
                await server.StartAsync(new ServerLaunchOptions(oldServer, Path.Combine(testDirectory, "old-data"), ClientProfile.Richonline, false));
                Record("old_server_failure_reason", false, "Old server unexpectedly accepted options");
                await server.StopAsync();
            }
            catch (ControlException error)
            {
                Record("old_server_failure_reason", error.Code == "early_exit" && error.Message.Contains("option_unknown", StringComparison.Ordinal)
                    && error.Message.Contains(Path.GetFullPath(oldServer), StringComparison.Ordinal) && !server.IsAlive, error.Message);
                lock (logs) Record("stderr_drained", logs.Any(line => line.Contains("option_unknown", StringComparison.Ordinal)));
            }
        }
        catch (Exception error) { Record("unexpected_failure", false, error.ToString()); }
        var passed = results.All(item => item?["passed"]?.GetValue<bool>() == true);
        File.WriteAllText(Path.Combine(outputDirectory, "result.json"), new JsonObject
        { ["passed"] = passed, ["tests"] = results }.ToJsonString(JsonFormatting.Indented));
        return passed ? 0 : 1;
    }
}
