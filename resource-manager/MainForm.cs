using System.Diagnostics;

namespace RichOnline.Resources;

internal sealed class MainForm : Form
{
    private static void TraceStage(string stage) => File.AppendAllText(@"F:\大富翁online\Richonline\resource-manager\test-artifacts\startup-hang\stages.txt", DateTime.Now.ToString("O") + " " + stage + "\n");
    private ResourceStore store;
    private readonly ListBox categories = new() { Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, ItemHeight = 44, DrawMode = DrawMode.OwnerDrawFixed, BackColor = Color.FromArgb(241, 245, 251) };
    private readonly DataGridView files = Ui.Grid();
    private readonly TextBox search = new() { Width = 310, PlaceholderText = "搜索资源名称或文件位置", Margin = new Padding(8, 8, 8, 8) };
    private readonly Panel editorHost = new() { Dock = DockStyle.Fill, BackColor = Color.White };
    private readonly Label title = new() { Text = "选择资源开始维护", Font = new Font("Microsoft YaHei UI", 15, FontStyle.Bold), AutoSize = true, Margin = new Padding(10, 8, 8, 2) };
    private readonly Label location = Ui.Label("");
    private readonly ToolStripStatusLabel status = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly Button save;
    private List<ResourceFile> inventory = [];
    private List<ResourceFile> visible = [];
    private ResourceEditor? editor;
    private string? opened, hash;
    private bool filtering, loading;
    public MainForm(string root)
    {
        TraceStage("constructor enter");
        store = new ResourceStore(root);
        Text = "大富翁 Online · 资源工作台"; Font = new Font("Microsoft YaHei UI", 10); ForeColor = Ui.Ink;
        Size = new Size(1440, 900); MinimumSize = new Size(1100, 720); StartPosition = FormStartPosition.CenterScreen; BackColor = Color.White; KeyPreview = true;
        var navigation = new Panel { Dock = DockStyle.Left, Width = 166, Padding = new Padding(12, 20, 6, 12), BackColor = categories.BackColor };
        navigation.Controls.Add(categories);
        var brand = new Label { Text = "资源工作台", Dock = DockStyle.Top, Height = 62, Font = new Font(Font.FontFamily, 16, FontStyle.Bold), ForeColor = Ui.Accent };
        navigation.Controls.Add(brand);
        categories.Items.AddRange(ResourceStore.Categories);
        TraceStage("navigation prepared");
        categories.DrawItem += (_, e) =>
        {
            if (e.Index < 0) return; bool selected = (e.State & DrawItemState.Selected) != 0;
            using var brush = new SolidBrush(selected ? Color.FromArgb(219, 232, 251) : categories.BackColor); e.Graphics.FillRectangle(brush, e.Bounds);
            TextRenderer.DrawText(e.Graphics, categories.Items[e.Index].ToString(), Font, new Rectangle(e.Bounds.X + 12, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height), selected ? Ui.Accent : Ui.Ink, TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
        };
        var split = new SplitContainer { Dock = DockStyle.Fill, Size = new Size(1250, 800), SplitterDistance = 350, Panel1MinSize = 280, Panel2MinSize = 570, BackColor = Color.FromArgb(229, 234, 241), SplitterWidth = 5 };
        files.Columns.Add("name", "资源名称"); files.Columns.Add("kind", "分类"); files.Columns[1].FillWeight = 36;
        files.ReadOnly = true; files.VirtualMode = true;
        files.CellValueNeeded += (_, e) => { if (e.RowIndex < visible.Count) e.Value = e.ColumnIndex == 0 ? visible[e.RowIndex].DisplayName : visible[e.RowIndex].Category; };
        files.CellToolTipTextNeeded += (_, e) => { if (e.RowIndex >= 0 && e.RowIndex < visible.Count) e.ToolTipText = visible[e.RowIndex].RelativePath; };
        split.Panel1.Controls.Add(files); split.Panel1.Controls.Add(Ui.Row(Ui.Label("搜索资源"), search));
        split.Panel1.SizeChanged += (_, _) => search.Width = Math.Max(150, split.Panel1.ClientSize.Width - 32);
        TraceStage("split prepared");
        split.Panel2.Controls.Add(editorHost);
        save = Ui.Button("保存修改  Ctrl+S", Save); save.Enabled = false; save.BackColor = Ui.Accent; save.ForeColor = Color.White;
        var heading = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, BackColor = Color.White };
        heading.Controls.Add(title); heading.Controls.Add(location);
        split.Panel2.Controls.Add(Ui.Row(save, Ui.Button("重新载入", ReloadSelected), Ui.Button("导出原文件", Export), Ui.Button("替换文件", Replace), Ui.Button("复制资源", Duplicate), Ui.Button("移入回收站", Delete)));
        split.Panel2.Controls.Add(heading);
        TraceStage("heading prepared");
        var toolbar = Ui.Row(Ui.Button("打开游戏目录", ChangeRoot), Ui.Button("导入资源", Import), Ui.Button("刷新列表", () => Ui.Guard(() => _ = ScanAsync())), Ui.Button("历史与回收站", History), Ui.Button("使用说明", Help));
        var strip = new StatusStrip(); strip.Items.Add(status);
        TraceStage("add split"); Controls.Add(split); TraceStage("add toolbar"); Controls.Add(toolbar); TraceStage("add navigation"); Controls.Add(navigation); TraceStage("add status"); Controls.Add(strip);
        categories.SelectedIndexChanged += (_, _) => Filter();
        search.TextChanged += (_, _) => Filter();
        files.SelectionChanged += (_, _) => { if (!filtering && !loading) OpenSelection(); };
        files.CellClick += (_, _) => { if (!filtering && !loading) OpenSelection(); };
        KeyDown += (_, e) => { if (e.Control && e.KeyCode == Keys.S) { e.SuppressKeyPress = true; Ui.Guard(Save); } };
        FormClosing += (_, e) => { if (!ConfirmLeave()) e.Cancel = true; };
        categories.SelectedIndex = 0; Shown += async (_, _) => await ScanAsync();
        TraceStage("constructor complete");
    }
    private async Task ScanAsync()
    {
        if (loading) return;
        loading = true; status.Text = "正在读取游戏资源…";
        try { TraceStage("scan begin"); inventory = await Task.Run(store.Scan); TraceStage("scan end"); Filter(); TraceStage("filter end"); if (opened == null) Welcome(); TraceStage("welcome end"); }
        catch (Exception error) { MessageBox.Show(error.Message, "读取失败"); }
        finally { loading = false; status.Text = $"{store.Root}    ·    共 {inventory.Count:N0} 个资源文件"; }
    }
    private void Welcome()
    {
        ClearEditor();
        var tiles = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(24), BackColor = Color.White };
        foreach (string category in ResourceStore.Categories.Skip(1))
        {
            TraceStage("tile " + category);
            int count = inventory.Count(f => f.Category == category);
            var button = Ui.Button($"{category}\n{count:N0} 份资源", () =>
            {
                categories.SelectedItem = category;
                string? target = category switch { "角色" => "Data/Role.kpd", "道具卡" => "Data/Prop.kpd", "文本" => "Data/RichStr.kpd", _ => inventory.FirstOrDefault(f => f.Category == category)?.RelativePath };
                if (target != null) Open(target.Replace('/', Path.DirectorySeparatorChar));
            });
            button.Size = new Size(215, 105); button.AutoSize = false; button.TextAlign = ContentAlignment.MiddleLeft; button.Padding = new Padding(16); button.Margin = new Padding(8); tiles.Controls.Add(button);
        }
        TraceStage("add tiles begin"); editorHost.Controls.Add(tiles); TraceStage("add tiles end");
    }
    private void Filter()
    {
        filtering = true;
        try
        {
            string selected = categories.SelectedItem?.ToString() ?? "全部资源";
            visible = inventory.Where(f => (selected == "全部资源" || f.Category == selected) && (f.RelativePath + " " + f.DisplayName).Contains(search.Text, StringComparison.OrdinalIgnoreCase)).ToList();
            files.RowCount = visible.Count; files.ClearSelection(); files.Invalidate();
            status.Text = $"显示 {visible.Count:N0} / {inventory.Count:N0} 个资源    ·    {store.Root}";
        }
        finally { filtering = false; }
    }
    private string? Selection => files.CurrentRow is { Index: var i } && i < visible.Count ? visible[i].RelativePath : null;
    private void OpenSelection()
    {
        string? relative = Selection;
        if (relative == null || relative == opened || !ConfirmLeave()) return;
        Ui.Guard(() => Open(relative));
    }
    internal void Open(string relative)
    {
        byte[] bytes = store.Read(relative); string ext = Path.GetExtension(relative).ToLowerInvariant();
        ResourceEditor? next = null;
        try
        {
            next = ext switch
            {
                ".np" => new ImageEditor(bytes), ".emp" => new MapEditor(bytes),
                ".dat" when relative.StartsWith("Music", StringComparison.OrdinalIgnoreCase) || relative.StartsWith("Sound", StringComparison.OrdinalIgnoreCase) => new AudioEditor(bytes, AudioCatalog.Read(store, relative.StartsWith("Music", StringComparison.OrdinalIgnoreCase)), relative),
                ".kpd" or ".avt" => MakeText(bytes, true),
                ".txt" or ".ini" or ".csv" => MakeText(bytes, false),
                _ => null
            };
        }
        catch (InvalidDataException error) { next = new UnsupportedEditor(error.Message); }
        ClearEditor(); editor = next; opened = relative; hash = ResourceStore.Hash(bytes);
        title.Text = ResourceStore.DisplayName(relative); location.Text = relative + $"    ·    {bytes.Length / 1024.0:N1} KB";
        if (editor != null)
        {
            editorHost.Controls.Add(editor); editor.Changed += () => { save.Enabled = editor.CanSave && editor.Dirty; title.Text = ResourceStore.DisplayName(opened!) + "  ·  未保存"; };
        }
        else
        {
            editor = new UnsupportedEditor("这类资源目前支持导入、导出、替换、复制与恢复，尚未开放内部编辑。"); editorHost.Controls.Add(editor);
        }
        save.Enabled = false;
    }
    private static ResourceEditor MakeText(byte[] bytes, bool packed)
    {
        var resource = new TextResource(bytes, packed);
        return new TextTable(resource.Text).Records.Count > 0 ? new TableEditor(bytes, packed) : new PlainEditor(bytes, packed);
    }
    private void ClearEditor()
    {
        editor?.Dispose(); editor = null;
        foreach (Control control in editorHost.Controls.Cast<Control>().ToArray()) control.Dispose();
        editorHost.Controls.Clear(); save.Enabled = false;
    }
    private bool ConfirmLeave()
    {
        try { editor?.Flush(); } catch (Exception error) { MessageBox.Show(error.Message, "请检查内容"); return false; }
        if (editor?.Dirty != true) return true;
        var answer = MessageBox.Show("当前资源有未保存的修改，要先保存吗？", "未保存修改", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
        if (answer == DialogResult.Cancel) return false;
        if (answer == DialogResult.Yes) { try { Save(); } catch (Exception error) { MessageBox.Show(error.Message, "保存失败"); return false; } }
        return true;
    }
    private void Save()
    {
        if (editor == null || opened == null || !editor.CanSave) return;
        byte[] bytes = editor.Build(); store.Write(opened, bytes, hash); hash = ResourceStore.Hash(bytes); editor.Commit(); save.Enabled = false;
        title.Text = ResourceStore.DisplayName(opened); status.Text = "保存成功，修改前的版本已自动备份。";
        if (editor is AudioEditor) Open(opened);
    }
    private void ReloadSelected() { if (opened != null && ConfirmLeave()) Open(opened); }
    private void Export()
    {
        if (opened == null) return;
        using var dialog = new SaveFileDialog { FileName = Path.GetFileName(opened), Filter = "原始资源文件|*" + Path.GetExtension(opened) };
        if (dialog.ShowDialog(this) == DialogResult.OK) ExportBytes(dialog.FileName, store.Read(opened));
    }
    private void ExportBytes(string destination, byte[] bytes)
    {
        string relative = Path.GetRelativePath(store.Root, Path.GetFullPath(destination));
        if (ResourceStore.Folders.Contains(relative.Split(Path.DirectorySeparatorChar)[0], StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("请导出到资源目录之外。要修改游戏资源，请使用“替换文件”或“恢复到操作前”。");
        File.WriteAllBytes(destination, bytes);
    }
    private void Replace()
    {
        if (opened == null || !ConfirmLeave()) return;
        using var dialog = new OpenFileDialog { Filter = "同类资源|*" + Path.GetExtension(opened) };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        byte[] bytes = Packed.ReadFile(dialog.FileName); ValidateFile(opened, bytes);
        if (MessageBox.Show($"替换“{Path.GetFileName(opened)}”？原文件会自动备份。", "替换资源", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
        store.Write(opened, bytes, hash, "替换文件"); Open(opened);
    }
    private void Duplicate()
    {
        if (opened == null || !ConfirmLeave()) return;
        string? name = Ui.Ask("复制资源 · 填写新文件名", Path.GetFileNameWithoutExtension(opened) + "_副本" + Path.GetExtension(opened)); if (name == null) return;
        ValidateName(name, Path.GetExtension(opened)); string target = Path.Combine(Path.GetDirectoryName(opened)!, name);
        store.Write(target, store.Read(opened), null, "复制资源"); Open(target); _ = ScanAsync();
    }
    private static void ValidateName(string name, string? extension = null)
    {
        if (string.IsNullOrWhiteSpace(name) || Path.GetFileName(name) != name || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.EndsWith('.') || name.EndsWith(' ')) throw new InvalidDataException("请填写有效文件名，不要包含目录。");
        if (extension != null && !Path.GetExtension(name).Equals(extension, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("请保留原文件扩展名。");
    }
    private void Delete()
    {
        if (opened == null || !ConfirmLeave()) return;
        if (MessageBox.Show($"将“{Path.GetFileName(opened)}”移入资源回收站？使用它的游戏内容可能受影响。", "移入回收站", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK) return;
        store.Delete(opened, hash!); ClearEditor(); opened = null; hash = null; title.Text = "资源已移入回收站"; location.Text = "可通过“历史与回收站”恢复。"; _ = ScanAsync();
    }
    private void Import()
    {
        if (!ConfirmLeave()) return;
        using var dialog = new OpenFileDialog { Filter = "游戏资源|*.emp;*.kpd;*.np;*.dat;*.avt;*.ui;*.ms;*.txt;*.ini" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string ext = Path.GetExtension(dialog.FileName).ToLowerInvariant();
        string defaultFolder = ext switch { ".emp" => "Map", ".np" => "Tex", ".avt" => "Avatar", ".ui" => "Interface", ".ms" => "SysRes", ".dat" => categories.SelectedItem?.ToString() == "音乐" ? "Music" : "Sound", _ => "Data" };
        string? relative = Ui.Ask("导入到游戏目录（填写资源相对位置）", Path.Combine(defaultFolder, Path.GetFileName(dialog.FileName))); if (relative == null) return;
        byte[] bytes = Packed.ReadFile(dialog.FileName); ValidateFile(relative, bytes); store.Write(relative, bytes, null, "导入资源"); Open(relative); _ = ScanAsync();
    }
    internal static void ValidateFile(string relative, byte[] bytes)
    {
        switch (Path.GetExtension(relative).ToLowerInvariant())
        {
            case ".emp": _ = MapResource.Load(bytes); break;
            case ".np": using (PictureResource.Load(bytes)) { } break;
            case ".kpd": case ".avt": _ = new TextResource(bytes, true); break;
            case ".dat" when relative.StartsWith("Music", StringComparison.OrdinalIgnoreCase) || relative.StartsWith("Sound", StringComparison.OrdinalIgnoreCase):
                var audio = AudioPackage.Load(bytes);
                if (audio.Music != relative.StartsWith("Music", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("音乐包应放入 Music，音效包应放入 Sound。");
                break;
        }
    }
    private void ChangeRoot()
    {
        if (loading || !ConfirmLeave()) return;
        using var dialog = new FolderBrowserDialog { Description = "选择游戏目录", InitialDirectory = store.Root };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        var replacement = new ResourceStore(dialog.SelectedPath); ClearEditor(); opened = null; store = replacement; title.Text = "选择资源开始维护"; location.Text = ""; _ = ScanAsync();
    }
    private void History()
    {
        if (!ConfirmLeave()) return;
        using var form = new Form { Text = "历史与回收站", Size = new Size(980, 620), Font = Font, StartPosition = FormStartPosition.CenterParent };
        var grid = Ui.Grid(); grid.ReadOnly = true; grid.Columns.Add("time", "时间"); grid.Columns.Add("action", "操作"); grid.Columns.Add("path", "资源位置"); grid.Columns[2].FillWeight = 200;
        var revisions = store.History(); foreach (var r in revisions) { int row = grid.Rows.Add(r.Time.ToString("yyyy-MM-dd HH:mm:ss"), r.Action, r.Path); grid.Rows[row].Tag = r; }
        form.Controls.Add(grid); form.Controls.Add(Ui.Row(Ui.Button("恢复到操作前", () =>
        {
            if (grid.CurrentRow?.Tag is not Revision r) return;
            if (MessageBox.Show("恢复这次操作之前的文件？当前版本也会保留备份。", "恢复资源", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
            store.Restore(r); if (opened == r.Path) Open(r.Path); form.Close(); _ = ScanAsync();
        }), Ui.Button("导出备份", () =>
        {
            if (grid.CurrentRow?.Tag is not Revision r || r.Blob == null) return;
            using var dialog = new SaveFileDialog { FileName = Path.GetFileName(r.Path) };
            if (dialog.ShowDialog(form) == DialogResult.OK && Path.GetFileName(r.Blob) == r.Blob) ExportBytes(dialog.FileName, File.ReadAllBytes(Path.Combine(store.Root, ".resource-workbench", "history", r.Blob)));
        })));
        form.ShowDialog(this);
    }
    private void Help() => MessageBox.Show("1. 左侧选择资源分类，搜索文件，点击打开。\n2. 图片可预览动画和导出透明图片；声音可试听、替换和导出。\n3. 角色、道具卡和文本在表格中编辑。地图支持开局资金与地产数值维护。\n4. 点击保存或按 Ctrl+S，原版本会自动备份。\n5. 删除的资源可从“历史与回收站”恢复。\n\n新增文件不会自动加入游戏入口；资源关联仍需按游戏设定配置。改动后请重新启动游戏进行验证。", "资源工作台使用说明");
    internal async Task RenderEvidence(string directory)
    {
        Directory.CreateDirectory(directory); await ScanAsync();
        foreach (string relative in new[] { "Data/Role.kpd", "Data/Prop.kpd", "Map/BS_1_1.emp", "Music/mus0000.dat", "Data/RichStr.kpd", "Tex/17/08950.np" })
        {
            categories.SelectedItem = ResourceStore.Category(relative);
            Open(relative.Replace('/', Path.DirectorySeparatorChar)); await Task.Delay(100); PerformLayout();
            using var bitmap = new Bitmap(Width, Height); DrawToBitmap(bitmap, new Rectangle(Point.Empty, Size)); bitmap.Save(Path.Combine(directory, Path.GetFileNameWithoutExtension(relative) + ".png"));
        }
        Size = MinimumSize; PerformLayout();
        using var small = new Bitmap(Width, Height); DrawToBitmap(small, new Rectangle(Point.Empty, Size)); small.Save(Path.Combine(directory, "minimum-window.png"));
    }
    protected override void Dispose(bool disposing) { if (disposing) editor?.Dispose(); base.Dispose(disposing); }
}

internal sealed class UnsupportedEditor : ResourceEditor
{
    public UnsupportedEditor(string message) { Controls.Add(new Label { Text = message, Dock = DockStyle.Top, Height = 110, Padding = new Padding(24), ForeColor = Ui.Muted }); }
    public override bool CanSave => false;
    public override byte[] Build() => throw new InvalidOperationException("这类资源尚未开放内部编辑。");
}
