using System.Collections.Concurrent;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed partial class MainForm
{
    private const int MaximumLogs = 2000;
    private const int MaximumLogsPerTick = 500;
    // 后台线程只入队，界面定时器分批消费；待展示和历史队列都保留最近的有限行数。
    private readonly ConcurrentQueue<LogRow> pendingLogs = new();
    private readonly Queue<LogRow> logs = new();
    private readonly ListView logView = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
        GridLines = true, HideSelection = false, Font = new Font("Consolas", 9) };
    private readonly ComboBox logLevel = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
    private readonly CheckBox logPaused = new() { Text = "暂停展示", AutoSize = true };
    private readonly Label logCount = new() { AutoSize = true };
    private readonly System.Windows.Forms.Timer logTimer = new() { Interval = 200 };
    private sealed record LogRow(string Time, string Level, string Event, string Detail);

    private void BuildLogsPage()
    {
        var page = Ui.Page("日志");
        logView.Columns.Add("时间", 190); logView.Columns.Add("级别", 80);
        logView.Columns.Add("事件", 180); logView.Columns.Add("详情 / 原始日志", 650);
        logLevel.Items.AddRange(["全部", "info", "warning", "error"]); logLevel.SelectedIndex = 0;
        logLevel.SelectedIndexChanged += (_, _) => RenderLogs();
        logPaused.CheckedChanged += (_, _) => { if (!logPaused.Checked) RenderLogs(); };
        page.Controls.Add(logView);
        page.Controls.Add(Ui.Row(logLevel, logPaused, Ui.Button("复制选中日志", (_, _) =>
        {
            var selected = logView.SelectedItems.Cast<ListViewItem>().Select(item =>
                string.Join("\t", item.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(sub => sub.Text)));
            var text = string.Join(Environment.NewLine, selected);
            if (text.Length > 0) Clipboard.SetText(text);
        }), Ui.Button("打开日志目录", (_, _) => OpenDirectory(Path.Combine(dataPath.Text, "logs"))), logCount));
        tabs.TabPages.Add(page);
        logTimer.Tick += (_, _) =>
        {
            // 暂停只冻结展示，仍持续消费并限流，避免恢复时积压所有历史输出。
            if (DrainPendingLogs() > 0 && !logPaused.Checked) RenderLogs();
        };
        logTimer.Start();
    }
    private int DrainPendingLogs()
    {
        var processed = 0;
        while (processed < MaximumLogsPerTick && pendingLogs.TryDequeue(out var row))
        {
            processed++;
            logs.Enqueue(row);
            if (logs.Count > MaximumLogs) logs.Dequeue();
        }
        return processed;
    }
    private void QueueLog(string level, string raw)
    {
        if (raw.Length > ControlClient.MaximumFrame) raw = raw[..ControlClient.MaximumFrame];
        var row = new LogRow(DateTimeOffset.Now.ToString("HH:mm:ss.fff"), level, "raw", raw);
        try
        {
            if (JsonNode.Parse(raw) is JsonObject json)
                row = new LogRow(json["timestamp"]?.ToString() ?? row.Time, json["level"]?.ToString() ?? level,
                    json["event"]?.ToString() ?? "json", raw);
        }
        catch (System.Text.Json.JsonException) { }
        pendingLogs.Enqueue(row);
        while (pendingLogs.Count > MaximumLogs) pendingLogs.TryDequeue(out _);
    }
    private void RenderLogs()
    {
        var filter = logLevel.SelectedItem?.ToString();
        var selectedRows = logView.SelectedItems.Cast<ListViewItem>().Select(item => item.Tag).ToHashSet();
        logView.BeginUpdate(); logView.Items.Clear();
        foreach (var row in logs.Where(row => filter == "全部" || row.Level == filter))
        {
            var item = new ListViewItem([row.Time, row.Level, row.Event, row.Detail]) { Tag = row,
                Selected = selectedRows.Contains(row) };
            logView.Items.Add(item);
        }
        logCount.Text = $"保留最近 {logs.Count}/{MaximumLogs} 行";
        logView.EndUpdate();
    }
}
