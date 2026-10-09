using System.Diagnostics;
using System.Drawing.Imaging;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed partial class MainForm
{
    public static int RunGuiSmokeTest(string outputDirectory, string[] args)
    {
        var directory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(directory);
        var checks = new JsonArray();
        var result = new JsonObject { ["ok"] = false, ["checks"] = checks,
            ["method"] = "WinForms message loop and actual button PerformClick; DrawToBitmap is not an OS screenshot" };
        void Require(bool condition, string name)
        {
            if (!condition) throw new InvalidOperationException(name);
            checks.Add(name);
        }
        try
        {
            // Exercise both installed layouts without depending on the developer's old checkout.
            var layout = Path.Combine(directory, "layout-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(layout);
            var settings = AdminLaunchSettings.Load(layout, []);
            Require(settings.Server == Path.Combine(layout, "server", "RichOnline.Server.exe")
                && settings.DataDirectory == Path.Combine(layout, "server", "data"), "client_root_defaults");
            File.WriteAllBytes(Path.Combine(layout, "RichOnline.Server.exe"), []);
            settings = AdminLaunchSettings.Load(layout, []);
            Require(settings.Server == Path.Combine(layout, "RichOnline.Server.exe")
                && settings.DataDirectory == Path.Combine(layout, "data")
                && settings.Client == Path.GetFullPath("../RnClient.exe", layout), "server_directory_defaults");
            File.WriteAllText(Path.Combine(layout, "RichOnline.Admin.launch.json"), "{\"server\":\"chosen.exe\",\"data-dir\":\"chosen-data\"}");
            Require(AdminLaunchSettings.Load(layout, []).Server == Path.Combine(layout, "chosen.exe"), "sidecar_precedence");
            Require(AdminLaunchSettings.Load(layout, ["--server", Path.Combine(layout, "override.exe")]).Server
                == Path.Combine(layout, "override.exe"), "command_line_precedence");

            using var form = new MainForm(args);
            Exception? uiError = null;
            form.testError = error => uiError = error;
            async Task WaitForUiAsync()
            {
                var timer = Stopwatch.StartNew();
                while (form.busy && timer.Elapsed < TimeSpan.FromSeconds(30)) await Task.Delay(25);
                if (uiError is not null) throw new InvalidOperationException("GUI operation failed", uiError);
                Require(!form.busy, "button_operation_completed");
            }
            form.Shown += async (_, _) =>
            {
                try
                {
                    Require(File.Exists(form.serverPath.Text) && File.Exists(form.clientPath.Text)
                        && File.Exists(form.clientConfigPath.Text), "installed_paths_exist");
                    form.startButton.PerformClick();
                    await WaitForUiAsync();
                    Require(form.server.IsAlive && form.managementReady && !form.startButton.Enabled && form.stopButton.Enabled,
                        "start_button_owns_ready_server");
                    var status = await form.SendAsync("status");
                    foreach (var listener in new[] { "lobbyReady", "httpReady", "blackReady", "gameListenerReady" })
                        Require(status[listener]?.GetValue<bool>() == true, listener);
                    Require(status["clientProfile"]?.GetValue<string>() == "richonline", "richonline_profile");
                    result["status"] = status.DeepClone();
                    await form.RefreshAccountsAsync();
                    Require(form.totalAccounts > 0, "migrated_accounts_readable");
                    result["accountCount"] = form.totalAccounts;
                    await form.ReadSettingsAsync();
                    Require(form.loadedRevision is not null, "settings_page_reads_revision");
                    form.tabs.SelectedIndex = 0;
                    form.Refresh();
                    using (var bitmap = new Bitmap(form.Width, form.Height))
                    {
                        form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, form.Size));
                        bitmap.Save(Path.Combine(directory, "service-page.png"), ImageFormat.Png);
                    }
                    form.stopButton.PerformClick();
                    await WaitForUiAsync();
                    Require(!form.server.IsAlive && form.startButton.Enabled && !form.stopButton.Enabled,
                        "stop_button_releases_owned_server");
                    // Verify restarting the same data directory releases its process lock.
                    form.startButton.PerformClick();
                    await WaitForUiAsync();
                    Require(form.server.IsAlive && form.managementReady, "restart_button_same_data_directory");
                    result["ok"] = true;
                }
                catch (Exception error) { result["error"] = error.ToString(); }
                finally { form.Close(); }
            };
            Application.Run(form);
            Require(!form.server.IsAlive, "close_window_stops_owned_server");
        }
        catch (Exception error) { result["ok"] = false; result["error"] = error.ToString(); }
        File.WriteAllText(Path.Combine(directory, "gui-result.json"), result.ToJsonString(JsonFormatting.Indented));
        return result["ok"]?.GetValue<bool>() == true ? 0 : 1;
    }
}
