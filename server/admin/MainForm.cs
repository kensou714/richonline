using System.Diagnostics;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed partial class MainForm : Form
{
    private readonly ServerProcess server = new();
    private readonly TabControl tabs = new() { Dock = DockStyle.Fill };
    private readonly Label statusLabel = new() { AutoSize = true, Text = "管理服务：未启动    游戏服务：未验证" };
    private readonly TextBox serverPath = Ui.Text("C++ 服务端路径");
    private readonly TextBox dataPath = Ui.Text("服务数据目录");
    private readonly TextBox clientPath = Ui.Text("游戏客户端路径");
    private readonly TextBox clientConfigPath = Ui.Text("客户端 KPD 配置路径");
    private readonly NumericUpDown clientArea = new() { Minimum = 0, Maximum = 255, Dock = DockStyle.Left, AccessibleName = "客户端区域编号" };
    private readonly ComboBox clientProfile = new() { DropDownStyle = ComboBoxStyle.DropDownList,
        Dock = DockStyle.Fill, AccessibleName = "客户端版本及账号编码" };
    private readonly CheckBox adoptClientProfile = new() { AutoSize = true, Text = "确认未标记迁移库采用所选编码（仅登记，不修改密码）" };
    private readonly TextBox statusDetails = Ui.Text("服务实例详情", true);
    private readonly List<Control> commandButtons = [];
    private readonly List<Control> servicePathPickers = [];
    private readonly Button startButton;
    private readonly Button stopButton;
    private bool busy;
    private bool closing;
    private bool managementReady;
    private Action<Exception>? testError;

    public MainForm(string[] args)
    {
        Text = "RichOnline · 服务端管理器";
        Font = new Font("Microsoft YaHei UI", 10);
        Size = new Size(1120, 780); MinimumSize = new Size(900, 640);
        StartPosition = FormStartPosition.CenterScreen;
        var launch = AdminLaunchSettings.Load(AppContext.BaseDirectory, args);
        serverPath.Text = launch.Server;
        dataPath.Text = launch.DataDirectory;
        clientPath.Text = launch.Client;
        clientConfigPath.Text = launch.ClientConfig;
        clientProfile.Items.AddRange(["新版 Richonline · 繁体 · Big5（CP950）", "旧版 Original · 简体 · GBK（CP936）"]);
        clientProfile.SelectedIndex = launch.Profile == ClientProfile.Richonline ? 0 : 1;
        clientProfile.SelectedIndexChanged += (_, _) => adoptClientProfile.Checked = false;
        dataPath.TextChanged += (_, _) => adoptClientProfile.Checked = false;
        var header = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true,
            FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(Ui.PagePadding) };
        header.Controls.Add(new Label { Text = "RichOnline 服务端管理", Font = new Font(Font.FontFamily, 18, FontStyle.Bold), AutoSize = true });
        header.Controls.Add(statusLabel);
        Controls.Add(tabs); Controls.Add(header);
        startButton = Ui.Button("启动服务端", async (_, _) => await RunUiAsync(StartServerAsync));
        stopButton = Ui.Button("停止服务端", async (_, _) => await RunUiAsync(StopServerAsync));
        BuildServicePage(); BuildAccountsPage(); BuildSettingsPage(); BuildLogsPage(); BuildBackupPage();
        server.Log += QueueLog;
        server.Exited += () => Post(() => { managementReady = false; statusLabel.Text = "管理服务：已退出    游戏服务：未运行"; RefreshButtons(); });
        FormClosing += OnClosing;
        var diagnosticsIndex = Array.IndexOf(args, "--render-diagnostics");
        var renderDiagnostics = diagnosticsIndex >= 0 && diagnosticsIndex + 1 < args.Length;
        if (launch.StartServer || renderDiagnostics)
            Shown += async (_, _) =>
            {
                await RunUiAsync(async () =>
                {
                    // 两种显式入口共用一次启动，保留 stdout/stderr 与进程所有权。
                    if (launch.StartServer || args.Contains("--diagnostic-connect"))
                        await StartServerAsync();
                    if (renderDiagnostics)
                    {
                        if (managementReady)
                        {
                            await RefreshAccountsAsync();
                            await ReadSettingsAsync();
                        }
                        BeginInvoke(() => RenderDiagnostics(args[diagnosticsIndex + 1]));
                    }
                });
            };
        RefreshButtons();
    }

    private void BuildServicePage()
    {
        var page = Ui.Page("服务");
        page.AutoScroll = true;
        var fields = Ui.Fields();
        Ui.Field(fields, "C++ 服务端", PathPicker(serverPath, false));
        Ui.Field(fields, "独立数据目录", PathPicker(dataPath, true));
        Ui.Field(fields, "客户端版本", clientProfile);
        Ui.Field(fields, "迁移库编码确认", adoptClientProfile);
        Ui.Field(fields, "编码说明", new Label { AutoSize = true, MaximumSize = new Size(700, 0),
            Text = "版本必须与建库时的账号编码一致。无标记的迁移库仅在明确来源后勾选；登记不转换现有密码，也不重置账号。" });
        Ui.Field(fields, "游戏客户端", PathPicker(clientPath, false));
        Ui.Field(fields, "客户端配置", PathPicker(clientConfigPath, false));
        Ui.Field(fields, "区域编号", clientArea);
        statusDetails.ReadOnly = true;
        statusDetails.Dock = DockStyle.Top; statusDetails.Height = 180;
        statusDetails.Text = "尚未连接管理服务。\r\n选择服务端后启动，管理器会核实进程与就绪响应。\r\n游戏是否可用由服务端单独报告。";
        endClientButton = Ui.Button("结束客户端进程", async (_, _) => await RunUiAsync(EndClientAsync));
        var actions = Ui.Row(startButton, stopButton,
            Ui.Button("启动客户端", (_, _) => LaunchClient()),
            endClientButton,
            ManagedButton("刷新状态", async () => ShowStatus(await SendAsync("status"))));
        page.Controls.Add(statusDetails); page.Controls.Add(Ui.Row(clientActionResult)); page.Controls.Add(actions); page.Controls.Add(fields);
        tabs.TabPages.Add(page);
    }

    private Control PathPicker(TextBox input, bool directory)
    {
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        panel.Controls.Add(input);
        panel.Controls.Add(Ui.Button("浏览…", (_, _) =>
        {
            if (directory)
            {
                using var dialog = new FolderBrowserDialog { InitialDirectory = input.Text };
                if (dialog.ShowDialog(this) == DialogResult.OK) input.Text = dialog.SelectedPath;
            }
            else
            {
                using var dialog = new OpenFileDialog { Filter = input == clientConfigPath ? "客户端配置 (*.kpd)|*.kpd" : "可执行文件 (*.exe)|*.exe", FileName = input.Text };
                if (dialog.ShowDialog(this) == DialogResult.OK) input.Text = dialog.FileName;
            }
        }));
        if (input == serverPath || input == dataPath) servicePathPickers.Add(panel);
        return panel;
    }

    private Button ManagedButton(string text, Func<Task> action)
    {
        var button = Ui.Button(text, async (_, _) => await RunUiAsync(action));
        commandButtons.Add(button);
        return button;
    }

    private async Task StartServerAsync()
    {
        ResetDataViews();
        statusLabel.Text = "管理服务：启动中    游戏服务：未验证";
        var profile = clientProfile.SelectedIndex == 0 ? ClientProfile.Richonline : ClientProfile.Original;
        ShowStatus(await server.StartAsync(new ServerLaunchOptions(serverPath.Text, dataPath.Text, profile, adoptClientProfile.Checked)));
        adoptClientProfile.Checked = false;
    }
    private async Task StopServerAsync()
    {
        managementReady = false;
        ResetDataViews();
        statusLabel.Text = "管理服务：停止中    游戏服务：停止中";
        await server.StopAsync();
        statusLabel.Text = "管理服务：未启动    游戏服务：未运行";
    }
    private void ResetDataViews()
    {
        loadedAccount = null; loadedAccounts = []; totalAccounts = 0; accountOffset = 0;
        accountsGrid.Rows.Clear(); accountTotal.Text = "尚未读取账号。";
        foreach (var field in accountFields.Values) field.Clear();
        accountReason.Clear(); settingsEditor.Clear(); loadedRevision = null;
        settingsRevision.Text = "尚未读取服务配置。"; backupResult.Clear();
    }
    private void ShowStatus(JsonObject status)
    {
        managementReady = true;
        static string Listener(JsonObject response, string field) => response[field]?.GetValue<bool>() == true ? "监听正常" : "未监听／未知";
        var gameReady = status["gameReady"]?.GetValue<bool>() == true;
        statusLabel.Text = $"管理服务：已就绪（PID {status["pid"]}，版本 {status["clientProfile"]}）\r\n"
            + $"大厅：{Listener(status, "lobbyReady")}    HTTP：{Listener(status, "httpReady")}    黑名单：{Listener(status, "blackReady")}\r\n"
            + $"游戏端口：{Listener(status, "gameListenerReady")}\r\n"
            + $"完整协议覆盖：{(gameReady ? "服务端报告已就绪" : "尚未完成；已支持地图可连接，具体能力由服务端校验")}";
        statusDetails.Text = status.ToJsonString(JsonFormatting.Indented);
    }
    private void LaunchClient()
    {
        try
        {
            var start = ClientLaunch.Prepare(clientPath.Text, clientConfigPath.Text, clientArea.Value);
            using var launched = Process.Start(start);
            QueueLog("info", "client_started: " + launched?.Id);
        }
        catch (Exception error) { ShowError(error); }
    }
    private async Task<JsonObject> SendAsync(string command, JsonObject? payload = null)
    {
        var control = server.Control ?? throw new ControlException("service_unavailable", "请先启动管理服务。");
        try
        {
            var result = await control.SendAsync(command, payload);
            QueueLog("info", "command_ok: " + command);
            return result;
        }
        catch (Exception error)
        {
            var code = error is ControlException controlError ? controlError.Code : error.GetType().Name;
            QueueLog("error", $"command_failed: {command} [{code}] {error.Message}");
            throw;
        }
    }
    private async Task RunUiAsync(Func<Task> action)
    {
        if (busy) return;
        busy = true; RefreshButtons();
        try { await action(); }
        catch (Exception error) { ShowError(error); }
        finally { busy = false; RefreshButtons(); }
    }
    private void ShowError(Exception error)
    {
        var code = error is ControlException control ? control.Code : error.GetType().Name;
        var message = $"[{code}] {error.Message}";
        QueueLog("error", message);
        if (!server.IsAlive) statusLabel.Text = "管理服务：未运行或启动失败    游戏服务：未运行";
        if (testError is not null) { testError(error); return; }
        MessageBox.Show(this, message, "操作未完成", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
    private void RefreshButtons()
    {
        startButton.Enabled = !busy && !server.IsAlive;
        stopButton.Enabled = !busy && server.IsAlive;
        if (endClientButton is not null) endClientButton.Enabled = !busy;
        serverPath.ReadOnly = dataPath.ReadOnly = server.IsAlive || busy;
        clientProfile.Enabled = adoptClientProfile.Enabled = !server.IsAlive && !busy;
        foreach (var picker in servicePathPickers) picker.Enabled = !server.IsAlive && !busy;
        foreach (var button in commandButtons) button.Enabled = !busy && managementReady;
    }
    // 服务进程事件来自后台线程；控件更新必须投递到仍然有效的窗口线程。
    private void Post(Action action)
    {
        if (IsHandleCreated && !IsDisposed) BeginInvoke(action);
    }
    private async void OnClosing(object? sender, FormClosingEventArgs args)
    {
        if (closing) return;
        // 第一次关闭先等待服务清理；closing 允许收尾后的第二次 Close 真正销毁窗口。
        args.Cancel = true;
        if (busy) { QueueLog("warning", "操作仍在进行，请完成后再关闭窗口。"); return; }
        closing = true; Enabled = false;
        try { await server.StopAsync(); }
        finally { server.Dispose(); logTimer.Stop(); Close(); }
    }
}
