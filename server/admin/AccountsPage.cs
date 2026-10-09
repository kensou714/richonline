using System.Globalization;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed partial class MainForm
{
    private readonly DataGridView accountsGrid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
        MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells,
        ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize, RowHeadersVisible = false
    };
    private readonly Dictionary<string, TextBox> accountFields = [];
    private readonly TextBox accountReason = Ui.Text("账号修改原因");
    private readonly TextBox accountSearch = new() { Width = 180, AccessibleName = "筛选账号" };
    private readonly Label accountTotal = new() { AutoSize = true };
    private readonly Button previousAccounts = new() { Text = "上一页", AutoSize = true };
    private readonly Button nextAccounts = new() { Text = "下一页", AutoSize = true };
    private readonly TextBox createUsername = new() { Width = 160, AccessibleName = "新账号用户名" };
    private readonly TextBox createPassword = new() { Width = 160, AccessibleName = "新账号密码", UseSystemPasswordChar = true };
    private JsonObject? loadedAccount;
    private JsonArray loadedAccounts = [];
    private int accountOffset;
    private int totalAccounts;
    private static readonly (string Key, string Label)[] AccountColumns =
    [
        ("role_id", "角色 ID"), ("username", "账号"), ("name", "角色名"), ("model", "角色模型"),
        ("level", "等级"), ("experience", "经验"), ("coins", "M 点"), ("gold", "金豆"), ("bank", "银行"),
        ("wins", "胜局"), ("losses", "负局"), ("draws", "平局"), ("vip_level", "VIP 等级"),
        ("escapes", "逃跑次数"), ("purchase_score", "消费积分")
    ];

    private void BuildAccountsPage()
    {
        var page = Ui.Page("账号");
        foreach (var column in AccountColumns) accountsGrid.Columns.Add(column.Key, column.Label);
        accountsGrid.SelectionChanged += (_, _) => LoadSelectedAccount();
        var split = new SplitContainer { Size = new Size(1000, 500), Dock = DockStyle.Fill,
            FixedPanel = FixedPanel.Panel2, SplitterDistance = 640, Panel1MinSize = 300, Panel2MinSize = 320 };
        split.Panel1.Controls.Add(accountsGrid);
        var editor = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(12, 0, 0, 0) };
        var fields = Ui.Fields();
        foreach (var column in AccountColumns.Skip(2))
        {
            var input = Ui.Text(column.Label);
            accountFields.Add(column.Key, input); Ui.Field(fields, column.Label, input);
        }
        Ui.Field(fields, "修改原因", accountReason);
        var save = ManagedButton("保存账号修改", SaveAccountAsync);
        editor.Controls.Add(Ui.Row(save)); editor.Controls.Add(fields); split.Panel2.Controls.Add(editor);
        previousAccounts.Click += async (_, _) => await RunUiAsync(async () => { accountOffset = Math.Max(0, accountOffset - 100); await RefreshAccountsAsync(); });
        nextAccounts.Click += async (_, _) => await RunUiAsync(async () => { if (accountOffset + 100 < totalAccounts) accountOffset += 100; await RefreshAccountsAsync(); });
        commandButtons.Add(previousAccounts); commandButtons.Add(nextAccounts);
        accountSearch.TextChanged += (_, _) => RenderAccounts();
        page.Controls.Add(split);
        page.Controls.Add(Ui.Row(ManagedButton("读取账号", RefreshAccountsAsync), previousAccounts, nextAccounts,
            new Label { Text = "当前页筛选", AutoSize = true }, accountSearch, accountTotal));
        page.Controls.Add(Ui.Row(new Label { Text = "创建账号", AutoSize = true }, createUsername,
            new Label { Text = "密码", AutoSize = true }, createPassword, ManagedButton("创建", CreateAccountAsync)));
        tabs.TabPages.Add(page);
    }

    private async Task RefreshAccountsAsync()
    {
        var result = await SendAsync("accounts.list", new JsonObject { ["offset"] = accountOffset, ["limit"] = 100 });
        loadedAccounts = result["accounts"] as JsonArray ?? throw new ControlException("invalid_accounts", "服务未返回账号数组。");
        totalAccounts = result["total"]?.GetValue<int>() ?? throw new ControlException("invalid_accounts", "服务未返回账号总数。");
        accountTotal.Text = $"总计 {totalAccounts}，第 {accountOffset / 100 + 1} 页";
        RenderAccounts();
    }
    private void RenderAccounts()
    {
        accountsGrid.Rows.Clear();
        var search = accountSearch.Text;
        foreach (var node in loadedAccounts)
        {
            if (node is not JsonObject account) continue;
            var summary = account["username"] + " " + account["name"];
            if (!summary.Contains(search, StringComparison.OrdinalIgnoreCase)) continue;
            var index = accountsGrid.Rows.Add(AccountColumns.Select(c => (object)(account[c.Key]?.ToString() ?? "")).ToArray());
            accountsGrid.Rows[index].Tag = account;
        }
        LoadSelectedAccount();
    }
    private void LoadSelectedAccount()
    {
        loadedAccount = accountsGrid.SelectedRows.Count > 0
            && accountsGrid.SelectedRows[0].Tag is JsonObject account ? (JsonObject)account.DeepClone() : null;
        foreach (var field in accountFields) field.Value.Text = loadedAccount?[field.Key]?.ToString() ?? "";
        accountReason.Clear();
    }
    private async Task SaveAccountAsync()
    {
        if (loadedAccount is null) throw new ControlException("selection_required", "请先选中一个账号。");
        if (string.IsNullOrWhiteSpace(accountReason.Text)) throw new ControlException("reason_required", "请填写修改原因。");
        var changes = new JsonObject();
        foreach (var field in accountFields)
        {
            var original = loadedAccount[field.Key]?.ToString() ?? "";
            if (original == field.Value.Text) continue;
            if (field.Key == "name") changes[field.Key] = field.Value.Text;
            else if (field.Key is "coins" or "gold" or "bank")
            {
                if (!double.TryParse(field.Value.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var amount) || !double.IsFinite(amount))
                    throw new ControlException("invalid_amount", "金额须为有效数字，使用小数点而非分组逗号。");
                changes[field.Key] = amount;
            }
            else
            {
                if (!long.TryParse(field.Value.Text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var integer))
                    throw new ControlException("invalid_integer", "等级、经验、模型及统计须为整数。");
                changes[field.Key] = integer;
            }
        }
        if (changes.Count == 0) throw new ControlException("changes_required", "账号字段没有变化。");
        // 原始快照随修改提交，服务端据此拒绝过期编辑；管理器不直接写数据库。
        await SendAsync("accounts.update", new JsonObject
        {
            ["role_id"] = loadedAccount["role_id"]?.DeepClone(), ["expected"] = loadedAccount.DeepClone(),
            ["changes"] = changes, ["reason"] = accountReason.Text
        });
        await RefreshAccountsAsync();
    }
    private async Task CreateAccountAsync()
    {
        // 密码仅用于本次创建请求，立即清空输入框；不得把请求载荷写入运行日志。
        var password = createPassword.Text;
        createPassword.Clear();
        await SendAsync("accounts.create", new JsonObject { ["username"] = createUsername.Text, ["password"] = password });
        createUsername.Clear(); accountOffset = 0;
        await RefreshAccountsAsync();
    }
}
