using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal static class ControlTests
{
    public static async Task<int> RunAsync(string[] args)
    {
        var evidence = Path.Combine(AppContext.BaseDirectory, "control-test-result.json");
        var results = new JsonArray();
        try
        {
            if (args.Length is not (2 or 3)) throw new ArgumentException("--self-test SERVER_EXE EMPTY_TEST_DATA_DIR [richonline|original]");
            var directory = Path.GetFullPath(args[1]);
            if (Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any())
                throw new ArgumentException("测试目录必须为空，以免修改现有账号。");
            using var process = new ServerProcess();
            var profile = args.Length == 3 ? ClientProfiles.Parse(args[2]) : ClientProfile.Richonline;
            var status = await process.StartAsync(new ServerLaunchOptions(args[0], directory, profile));
            Require(status["gameReady"]?.GetValue<bool>() == false, "Management ready remains distinct from game ready");
            results.Add("status_pid_and_readiness");
            Require(status["clientProfile"]?.GetValue<string>() == ClientProfiles.Argument(profile), "Explicit client profile round trip");
            results.Add("explicit_client_profile");
            var control = process.Control ?? throw new InvalidOperationException("Control missing after ready");
            var created = await control.SendAsync("accounts.create", new JsonObject { ["username"] = "admin_test", ["password"] = "local-test-Only92" });
            var account = created["account"] as JsonObject ?? throw new InvalidOperationException("Create account missing result");
            Require(account["username"]?.GetValue<string>() == "admin_test", "Account creation");
            Require(!account.ContainsKey("password") && !account.ContainsKey("password_hash") && !account.ContainsKey("salt"), "Public account omits credential material");
            results.Add("account_create_public");
            var updated = await control.SendAsync("accounts.update", new JsonObject
            {
                ["role_id"] = account["role_id"]?.DeepClone(), ["expected"] = account.DeepClone(),
                ["changes"] = new JsonObject { ["coins"] = 1234.5m }, ["reason"] = "isolated administrator integration test"
            });
            Require(updated["account"]?["coins"]?.GetValue<decimal>() == 1234.5m, "Fractional balance remains exact in control response");
            results.Add("account_cas_fractional_balance");
            await RequireFailureAsync(control, "accounts.update", new JsonObject
            {
                ["role_id"] = account["role_id"]?.DeepClone(), ["expected"] = account.DeepClone(),
                ["changes"] = new JsonObject { ["coins"] = 8 }, ["reason"] = "stale update must fail"
            });
            results.Add("account_stale_write_rejected");
            var config = await control.SendAsync("config.get");
            await control.SendAsync("config.update", new JsonObject
            {
                ["expectedRevision"] = config["revision"]?.DeepClone(), ["settings"] = config["settings"]?.DeepClone()
            });
            await RequireFailureAsync(control, "config.update", new JsonObject
            {
                ["expectedRevision"] = config["revision"]?.DeepClone(), ["settings"] = config["settings"]?.DeepClone()
            });
            results.Add("config_revision_conflict_rejected");
            var backup = await control.SendAsync("database.backup");
            Require(File.Exists(backup["path"]?.GetValue<string>()), "Online backup path exists");
            results.Add("database_backup");
            await process.StopAsync();
            Require(!process.IsAlive, "Owned process exited");
            results.Add("graceful_stop");
            VerifyClientConfigurationArgument(directory);
            results.Add("client_ascii_relative_config_staging");
            File.WriteAllText(evidence, new JsonObject { ["ok"] = true, ["tests"] = results }.ToJsonString(JsonFormatting.Indented));
            return 0;
        }
        catch (Exception error)
        {
            File.WriteAllText(evidence, new JsonObject { ["ok"] = false, ["tests"] = results.DeepClone(),
                ["error"] = error is ControlException control ? control.Code : error.GetType().Name,
                ["message"] = error.Message }.ToJsonString(JsonFormatting.Indented));
            return 1;
        }
    }
    private static void VerifyClientConfigurationArgument(string directory)
    {
        var clientDirectory = Path.Combine(directory, "client-launch-test");
        var sourceDirectory = Path.Combine(directory, "configuration with spaces");
        Directory.CreateDirectory(clientDirectory); Directory.CreateDirectory(sourceDirectory);
        var client = Path.Combine(clientDirectory, "test-client.exe");
        var configuration = Path.Combine(sourceDirectory, "local.kpd");
        var fixture = new byte[] { 0, 255, 17, 32, 0, 128 };
        File.WriteAllBytes(client, []); File.WriteAllBytes(configuration, fixture);
        var launch = ClientLaunch.Prepare(client, configuration, 0);
        var argument = launch.ArgumentList[0];
        Require(argument.Length < 128 && argument.All(character => character <= 127 && !char.IsWhiteSpace(character) && character != '"'),
            "Client configuration is short unquoted ASCII");
        Require(launch.WorkingDirectory == clientDirectory && launch.ArgumentList[1] == "0", "Fixed client working directory and area");
        Require(File.ReadAllBytes(Path.Combine(clientDirectory, argument)).SequenceEqual(fixture), "Staging preserves KPD bytes");
        Require(File.ReadAllBytes(configuration).SequenceEqual(fixture), "Source KPD remains unchanged");
    }
    private static void Require(bool condition, string behavior)
    {
        if (!condition) throw new InvalidOperationException("Failed: " + behavior);
    }
    private static async Task RequireFailureAsync(ControlClient control, string command, JsonObject payload)
    {
        try { await control.SendAsync(command, payload); }
        catch (ControlException) { return; }
        throw new InvalidOperationException("Expected rejection for " + command);
    }
}
