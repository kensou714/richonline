using System.Diagnostics;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed partial class MainForm
{
    private readonly TextBox settingsEditor = Ui.Text("服务配置 JSON", true);
    private readonly Label settingsRevision = new() { AutoSize = true, Text = "尚未读取服务配置。" };
    private long? loadedRevision;
    private readonly TextBox backupResult = Ui.Text("数据库备份结果", true);

    private void BuildSettingsPage()
    {
        var page = Ui.Page("设置");
        settingsEditor.Font = new Font("Consolas", 10);
        settingsEditor.AcceptsTab = true;
        page.Controls.Add(settingsEditor);
        page.Controls.Add(Ui.Row(ManagedButton("读取配置", ReadSettingsAsync), ManagedButton("保存配置", SaveSettingsAsync), settingsRevision));
        page.Controls.Add(new Label { Dock = DockStyle.Top, Height = 40,
            Text = "编辑服务端返回的完整 JSON。保存采用版本检查；配置已保存并不代表尚未实现的游戏功能已生效。" });
        tabs.TabPages.Add(page);
    }
    private async Task ReadSettingsAsync()
    {
        var result = await SendAsync("config.get");
        loadedRevision = result["revision"]?.GetValue<long>() ?? throw new ControlException("invalid_config", "服务未返回配置版本。");
        settingsEditor.Text = (result["settings"] as JsonObject
            ?? throw new ControlException("invalid_config", "服务未返回配置对象。")).ToJsonString(JsonFormatting.Indented);
        settingsRevision.Text = "已读取版本：" + loadedRevision;
    }
    private async Task SaveSettingsAsync()
    {
        if (loadedRevision is null) throw new ControlException("config_not_loaded", "请先读取配置。");
        var settings = JsonNode.Parse(settingsEditor.Text) as JsonObject
            ?? throw new ControlException("invalid_config", "配置必须是 JSON 对象。");
        // 用读取时的版本阻止覆盖他人的更新；失败时保留编辑框，供操作者核对差异。
        var result = await SendAsync("config.update", new JsonObject { ["expectedRevision"] = loadedRevision, ["settings"] = settings });
        loadedRevision = result["revision"]?.GetValue<long>() ?? throw new ControlException("invalid_config", "保存响应缺少新版本。");
        settingsRevision.Text = "已保存版本：" + loadedRevision;
    }
    private void BuildBackupPage()
    {
        var page = Ui.Page("备份");
        backupResult.ReadOnly = true;
        backupResult.Text = "服务端使用 SQLite 在线备份接口生成一致性副本。\r\n本管理器不会直接修改数据库。\r\n旧账号迁移属于显式离线操作，不会在启动时自动导入。";
        page.Controls.Add(backupResult);
        page.Controls.Add(Ui.Row(ManagedButton("生成数据库备份", async () =>
        {
            var result = await SendAsync("database.backup");
            backupResult.Text = result["path"]?.GetValue<string>()
                ?? throw new ControlException("invalid_backup", "服务未返回备份路径。");
        }), Ui.Button("打开数据目录", (_, _) => OpenDirectory(dataPath.Text))));
        tabs.TabPages.Add(page);
    }
    private void OpenDirectory(string path)
    {
        try
        {
            var directory = Path.GetFullPath(path);
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException("目录尚未创建：" + directory);
            using var opened = Process.Start(new ProcessStartInfo(directory) { UseShellExecute = true });
        }
        catch (Exception error) { ShowError(error); }
    }
}
