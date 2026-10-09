using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace RichOnline.Resources;

internal static class Ui
{
    public static readonly Color Ink = Color.FromArgb(35, 44, 62), Muted = Color.FromArgb(104, 115, 130), Accent = Color.FromArgb(34, 105, 202);
    public static Button Button(string text, Action action)
    {
        var button = new Button { Text = text, AutoSize = true, MinimumSize = new Size(76, 34), FlatStyle = FlatStyle.Flat, BackColor = Color.White, Margin = new Padding(4) };
        button.FlatAppearance.BorderColor = Color.FromArgb(216, 222, 230);
        button.Click += (_, _) => Guard(action); return button;
    }
    public static void Guard(Action action)
    {
        try { action(); } catch (Exception e) { MessageBox.Show(e.Message, "操作未完成", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }
    public static FlowLayoutPanel Row(params Control[] controls)
    {
        var panel = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(4), BackColor = Color.FromArgb(247, 249, 252) };
        panel.Controls.AddRange(controls); return panel;
    }
    public static Label Label(string text) => new() { Text = text, AutoSize = true, Margin = new Padding(8, 12, 8, 8), ForeColor = Muted };
    public static DataGridView Grid() => new()
    {
        Dock = DockStyle.Fill, BackgroundColor = Color.White, BorderStyle = BorderStyle.None, RowHeadersVisible = false,
        AllowUserToAddRows = false, AllowUserToDeleteRows = false, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect, MultiSelect = false, RowTemplate = { Height = 32 },
        AutoGenerateColumns = false, EnableHeadersVisualStyles = false, ColumnHeadersHeight = 36,
        ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(241, 244, 249), ForeColor = Ink },
        DefaultCellStyle = new DataGridViewCellStyle { SelectionBackColor = Color.FromArgb(226, 237, 253), SelectionForeColor = Ink },
        GridColor = Color.FromArgb(235, 239, 245)
    };
    public static string? Ask(string title, string value)
    {
        using var form = new Form { Text = title, Width = 540, Height = 180, StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false, Font = new Font("Microsoft YaHei UI", 10) };
        var box = new TextBox { Text = value, Dock = DockStyle.Top, Margin = new Padding(12) };
        var ok = Button("确定", () => form.DialogResult = DialogResult.OK);
        form.Controls.Add(Row(ok)); form.Controls.Add(box); form.Padding = new Padding(16); form.AcceptButton = ok;
        return form.ShowDialog() == DialogResult.OK ? box.Text.Trim() : null;
    }
}

internal abstract class ResourceEditor : UserControl
{
    public bool Dirty { get; protected set; }
    public event Action? Changed;
    protected void MarkChanged() { Dirty = true; Changed?.Invoke(); }
    public virtual bool CanSave => true;
    public virtual void Flush() { }
    public abstract byte[] Build();
    public virtual void Commit() => Dirty = false;
    protected ResourceEditor() { Dock = DockStyle.Fill; BackColor = Color.White; }
}

internal sealed class TableEditor : ResourceEditor
{
    private readonly TextResource resource;
    private readonly TextTable table;
    private readonly DataGridView records = Ui.Grid(), fields = Ui.Grid();
    private readonly TextBox search = new() { Width = 250, PlaceholderText = "搜索名称、编号或文字" };
    private readonly CheckBox advanced = new() { Text = "更多属性", AutoSize = true, Margin = new Padding(8, 10, 8, 8) };
    private TextRecord? current;
    private bool loading;
    public TableEditor(byte[] bytes, bool packed)
    {
        resource = new TextResource(bytes, packed); table = new TextTable(resource.Text);
        if (table.Records.Count == 0) throw new InvalidDataException("此文件没有可识别的条目，请使用文本编辑视图。");
        records.Columns.Add("id", "编号"); records.Columns.Add("name", "名称 / 文字"); records.Columns[0].FillWeight = 22; records.ReadOnly = true;
        records.Columns[0].MinimumWidth = 64;
        fields.Columns.Add("label", "属性"); fields.Columns.Add("value", "内容"); fields.Columns[0].ReadOnly = true; fields.Columns[0].FillWeight = 35;
        var split = new SplitContainer { Dock = DockStyle.Fill, SplitterDistance = 280, Size = new Size(800, 600), Panel1MinSize = 180, Panel2MinSize = 260 };
        split.Panel1.Controls.Add(records); split.Panel2.Controls.Add(fields);
        Controls.Add(split);
        Controls.Add(Ui.Row(Ui.Label("查找条目"), search, Ui.Button("复制为新条目", Duplicate), Ui.Button("删除条目", Delete), advanced));
        Controls.Add(Ui.Row(Ui.Label("双击右侧内容即可编辑；保存时保留原文件编码。")));
        records.SelectionChanged += (_, _) => Ui.Guard(ShowFields);
        search.TextChanged += (_, _) => Ui.Guard(Filter); advanced.CheckedChanged += (_, _) => Ui.Guard(ShowFields);
        fields.CellValidating += Validate;
        fields.CurrentCellDirtyStateChanged += (_, _) => { if (!loading && fields.IsCurrentCellDirty) MarkChanged(); };
        fields.DataError += (_, e) => { e.ThrowException = false; e.Cancel = true; };
        Filter();
    }
    private void Filter()
    {
        Flush(); records.Rows.Clear();
        foreach (var r in table.Records)
        {
            string id = table.Get(r, "indx"), name = table.Name(r);
            if (!(id + " " + name + " " + string.Join(" ", r.Fields.Keys.Select(k => table.Get(r, k)))).Contains(search.Text, StringComparison.OrdinalIgnoreCase)) continue;
            int row = records.Rows.Add(id, name); records.Rows[row].Tag = r;
        }
        ShowFields();
    }
    private void ShowFields()
    {
        Flush();
        loading = true;
        try
        {
            current = records.CurrentRow?.Tag as TextRecord; fields.Rows.Clear(); if (current == null) return;
            foreach (string key in current.Fields.Keys)
            {
                bool known = TextTable.Labels.TryGetValue(key, out var label);
                if (key.StartsWith("suit", StringComparison.OrdinalIgnoreCase)) { label = "服装 " + key[4..]; known = false; }
                if (!known && !advanced.Checked) continue;
                string value = table.Get(current, key);
                int row = fields.Rows.Add(label ?? "扩展项：" + key, DisplayValue(key, value)); fields.Rows[row].Tag = key;
                if (value is "true" or "false" || key.Equals("sex", StringComparison.OrdinalIgnoreCase))
                {
                    var combo = new DataGridViewComboBoxCell { DisplayStyle = DataGridViewComboBoxDisplayStyle.DropDownButton };
                    combo.Items.AddRange(key.Equals("sex", StringComparison.OrdinalIgnoreCase) ? ["男", "女"] : ["是", "否"]);
                    if (!combo.Items.Contains(DisplayValue(key, value))) combo.Items.Add(DisplayValue(key, value));
                    combo.Value = DisplayValue(key, value); fields.Rows[row].Cells[1] = combo;
                }
                if (value.Length > 45) { fields.Rows[row].Height = 82; fields.Rows[row].Cells[1].Style.WrapMode = DataGridViewTriState.True; }
                if (key.Equals("indx", StringComparison.OrdinalIgnoreCase)) fields.Rows[row].Cells[1].ReadOnly = true;
            }
            if (fields.Rows.Count == 0) fields.Rows.Add("提示", "勾选“更多属性”查看这份资源的扩展设定。");
        }
        finally { loading = false; }
    }
    private void Validate(object? sender, DataGridViewCellValidatingEventArgs e)
    {
        if (loading || current == null || e.ColumnIndex != 1 || fields.Rows[e.RowIndex].Tag is not string key) return;
        try
        {
            Apply(key, e.FormattedValue?.ToString() ?? "");
            fields.Rows[e.RowIndex].ErrorText = "";
        }
        catch (Exception error) { e.Cancel = true; fields.Rows[e.RowIndex].ErrorText = error.Message; }
    }
    private void Apply(string key, string value)
    {
        if (current == null) return;
        if (table.Get(current, key) is "true" or "false") value = value switch { "是" => "true", "否" => "false", _ => value };
        else value = RawValue(key, value);
        if (value == table.Get(current, key)) return;
        table.Set(current, key, value); MarkChanged();
        if (records.CurrentRow != null) records.CurrentRow.Cells[1].Value = table.Name(current);
    }
    private static string DisplayValue(string key, string value) => value switch
    {
        "true" => "是", "false" => "否", "boy" when key.Equals("sex", StringComparison.OrdinalIgnoreCase) => "男",
        "girl" when key.Equals("sex", StringComparison.OrdinalIgnoreCase) => "女", "CARD" when key.Equals("type", StringComparison.OrdinalIgnoreCase) => "卡片", _ => value
    };
    private static string RawValue(string key, string value) => value switch
    {
        "男" when key.Equals("sex", StringComparison.OrdinalIgnoreCase) => "boy",
        "女" when key.Equals("sex", StringComparison.OrdinalIgnoreCase) => "girl", "卡片" when key.Equals("type", StringComparison.OrdinalIgnoreCase) => "CARD", _ => value
    };
    private void Duplicate()
    {
        if (current == null || !fields.EndEdit()) return;
        table.Duplicate(current); search.Clear(); Filter(); records.CurrentCell = records.Rows[^1].Cells[0]; MarkChanged();
    }
    private void Delete()
    {
        if (current == null || MessageBox.Show($"删除“{table.Name(current)}”？保存后生效，可从历史恢复。", "删除条目", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
        Flush(); var removed = current; current = null;
        loading = true; fields.Rows.Clear(); loading = false;
        table.Delete(removed); Filter(); MarkChanged();
    }
    public override byte[] Build()
    {
        Flush();
        return resource.Save(table.ToString());
    }
    public override void Flush()
    {
        if (!fields.EndEdit()) throw new InvalidDataException("请先修正标记的内容。");
        foreach (DataGridViewRow row in fields.Rows)
            if (row.Tag is string key) Apply(key, row.Cells[1].Value?.ToString() ?? "");
    }
}

internal sealed class PlainEditor : ResourceEditor
{
    private readonly TextResource resource;
    private readonly TextBox text;
    public PlainEditor(byte[] bytes, bool compressed)
    {
        resource = new TextResource(bytes, compressed);
        text = new TextBox { Text = resource.Text, Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, AcceptsTab = true, AcceptsReturn = true };
        text.TextChanged += (_, _) => MarkChanged(); Controls.Add(text);
        Controls.Add(Ui.Row(Ui.Label("文本编辑 · 请保留原有编号和占位符")));
    }
    public override byte[] Build() => resource.Save(text.Text);
}

internal sealed class ImageEditor : ResourceEditor
{
    private PictureResource picture;
    private readonly PictureBox preview = new() { Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.CenterImage, BackColor = Color.FromArgb(227, 231, 236) };
    private readonly System.Windows.Forms.Timer timer = new();
    private readonly Label info = Ui.Label("");
    private readonly TrackBar frame = new() { Minimum = 1, Maximum = 1, Value = 1, Width = 180, TickStyle = TickStyle.None };
    private byte[] original;
    public ImageEditor(byte[] bytes)
    {
        original = bytes; picture = PictureResource.Load(bytes);
        frame.Maximum = picture.Frames.Count;
        Controls.Add(preview); Controls.Add(Ui.Row(Ui.Button("播放 / 暂停", () => timer.Enabled = !timer.Enabled), frame,
            Ui.Button("原大 / 适应", () => preview.SizeMode = preview.SizeMode == PictureBoxSizeMode.Zoom ? PictureBoxSizeMode.CenterImage : PictureBoxSizeMode.Zoom),
            Ui.Button("导出此帧", Export), Ui.Button("替换图片", Replace), Ui.Button("水平翻转", Flip), info));
        frame.ValueChanged += (_, _) => ShowFrame();
        timer.Tick += (_, _) => frame.Value = frame.Value % picture.Frames.Count + 1;
        ShowFrame();
    }
    private void ShowFrame()
    {
        preview.Image = picture.Frames[frame.Value - 1]; timer.Interval = picture.Durations[frame.Value - 1];
        info.Text = $"{preview.Image.Width} × {preview.Image.Height}  ·  第 {frame.Value} / {picture.Frames.Count} 帧";
    }
    private void Export()
    {
        using var dialog = new SaveFileDialog { Filter = "透明图片 (*.png)|*.png", FileName = "资源图片.png" };
        if (dialog.ShowDialog() == DialogResult.OK) picture.Frames[frame.Value - 1].Save(dialog.FileName, System.Drawing.Imaging.ImageFormat.Png);
    }
    private void Replace()
    {
        if (picture.Frames.Count != 1) throw new InvalidDataException("动画请使用整份 NP 文件替换，避免丢失动作帧。");
        using var dialog = new OpenFileDialog { Filter = "图片 (*.png;*.bmp)|*.png;*.bmp" };
        if (dialog.ShowDialog() != DialogResult.OK) return;
        using var bitmap = new Bitmap(dialog.FileName);
        if (bitmap.Size != picture.Frames[0].Size) throw new InvalidDataException($"请使用相同尺寸的图片：{picture.Frames[0].Width} × {picture.Frames[0].Height}。");
        SetPicture(PictureResource.FromImage(bitmap, original[0]));
    }
    private void Flip()
    {
        if (picture.Frames.Count != 1) throw new InvalidDataException("动画暂不支持逐帧修改。");
        using var copy = new Bitmap(picture.Frames[0]); copy.RotateFlip(RotateFlipType.RotateNoneFlipX); SetPicture(PictureResource.FromImage(copy, original[0]));
    }
    private void SetPicture(byte[] bytes)
    {
        var replacement = PictureResource.Load(bytes); timer.Stop(); preview.Image = null; picture.Dispose(); picture = replacement; original = bytes; ShowFrame(); MarkChanged();
    }
    public override byte[] Build() => original;
    protected override void Dispose(bool disposing) { if (disposing) { timer.Dispose(); preview.Image = null; picture.Dispose(); } base.Dispose(disposing); }
}

internal sealed class AudioEditor : ResourceEditor
{
    private readonly AudioPackage package;
    private readonly DataGridView grid = Ui.Grid();
    private readonly TrackBar volume = new() { Minimum = 0, Maximum = 100, Value = 70, Width = 110, TickStyle = TickStyle.None };
    private readonly string alias = "rw" + Guid.NewGuid().ToString("N");
    private readonly AudioCatalog? catalog;
    private readonly string relative;
    private string? temp;
    [DllImport("winmm.dll", CharSet = CharSet.Unicode)] private static extern int mciSendString(string command, StringBuilder? result, int capacity, IntPtr callback);
    public AudioEditor(byte[] bytes, AudioCatalog? catalog = null, string relative = "")
    {
        this.catalog = catalog; this.relative = relative;
        package = AudioPackage.Load(bytes); grid.ReadOnly = true;
        grid.Columns.Add("id", "声音编号"); grid.Columns.Add("format", "类型"); grid.Columns.Add("size", "大小"); grid.Columns.Add("state", "使用状态"); grid.Columns[3].FillWeight = 150;
        Controls.Add(grid); Controls.Add(Ui.Row(Ui.Button("试听", Play), Ui.Button("停止", Stop), volume, Ui.Button("导出声音", Export), Ui.Button("替换声音", Replace), Ui.Button("新增声音", Add), Ui.Button("删除声音", Delete)));
        Controls.Add(Ui.Row(Ui.Label("选择一条声音试听。相同编号以最后载入的声音为准。")));
        volume.ValueChanged += (_, _) => mciSendString($"setaudio {alias} volume to {volume.Value * 10}", null, 0, IntPtr.Zero);
        grid.SelectionChanged += (_, _) => Stop(); Reload();
    }
    private int Selected => grid.CurrentRow?.Index ?? -1;
    private void Reload()
    {
        grid.Rows.Clear(); for (int i = 0; i < package.Items.Count; i++)
        {
            var item = package.Items[i]; grid.Rows.Add(item.Id, AudioPackage.Extension(item.Content).TrimStart('.').ToUpperInvariant(), $"{item.Content.Length / 1024.0:N1} KB", package.Items.Skip(i + 1).Any(x => x.Id == item.Id) ? "被后项覆盖" : catalog?.State(relative, item.Id) ?? "本包有效");
        }
    }
    private void Play()
    {
        if (Selected < 0) return; Stop(); var bytes = package.Items[Selected].Content;
        temp = Path.Combine(Path.GetTempPath(), alias + AudioPackage.Extension(bytes)); File.WriteAllBytes(temp, bytes);
        string player = AudioPackage.Extension(bytes) == ".wav" ? "waveaudio" : "mpegvideo";
        int result = mciSendString($"open \"{temp}\" type {player} alias {alias}", null, 0, IntPtr.Zero);
        if (result != 0) { Stop(); throw new InvalidDataException("系统无法试听这条声音，可导出后使用音频软件检查。"); }
        mciSendString($"setaudio {alias} volume to {volume.Value * 10}", null, 0, IntPtr.Zero);
        if (mciSendString($"play {alias}", null, 0, IntPtr.Zero) != 0) { Stop(); throw new InvalidDataException("声音播放失败。"); }
    }
    private void Stop()
    {
        mciSendString($"close {alias}", null, 0, IntPtr.Zero);
        if (temp != null) { try { File.Delete(temp); } catch (IOException) { } temp = null; }
    }
    private void Export()
    {
        if (Selected < 0) return; var item = package.Items[Selected];
        using var dialog = new SaveFileDialog { FileName = "声音_" + item.Id + AudioPackage.Extension(item.Content), Filter = "声音文件|*" + AudioPackage.Extension(item.Content) };
        if (dialog.ShowDialog() == DialogResult.OK) File.WriteAllBytes(dialog.FileName, item.Content);
    }
    private byte[]? Choose(byte[] previous)
    {
        using var dialog = new OpenFileDialog { Filter = package.Music ? "MP3 音乐|*.mp3" : "WAV 音效|*.wav" };
        if (dialog.ShowDialog() != DialogResult.OK) return null;
        var bytes = Packed.ReadFile(dialog.FileName); AudioPackage.ValidateReplacement(previous, bytes); return bytes;
    }
    private void Replace()
    {
        if (Selected < 0) return; int index = Selected; var item = package.Items[index]; var bytes = Choose(item.Content); if (bytes == null) return;
        Stop(); package.Items[index] = item with { Content = bytes }; Reload(); grid.CurrentCell = grid.Rows[index].Cells[0]; MarkChanged();
    }
    private void Add()
    {
        string? input = Ui.Ask("新增声音编号", (package.Items.Max(x => x.Id) + 1).ToString()); if (input == null) return;
        if (!int.TryParse(input, out int id) || id < 0 || id > 32767 || package.Items.Any(x => x.Id == id)) throw new InvalidDataException("请输入未使用的编号（0—32767）。");
        if (catalog?.Effective.TryGetValue(id, out string? existing) == true && MessageBox.Show($"编号 {id} 已用于{ResourceStore.DisplayName(existing)}。继续新增会形成同编号覆盖，是否继续？", "编号已被使用", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
        var bytes = Choose(package.Items[0].Content); if (bytes == null) return;
        package.Items.Add(new(id, bytes)); Reload(); MarkChanged();
    }
    private void Delete()
    {
        if (Selected < 0) return;
        if (package.Items.Count == 1) throw new InvalidDataException("资源包至少需要一条声音。");
        if (MessageBox.Show("删除选中的声音？保存后生效。", "删除声音", MessageBoxButtons.OKCancel) != DialogResult.OK) return;
        Stop(); package.Items.RemoveAt(Selected); Reload(); MarkChanged();
    }
    public override byte[] Build() => package.Save();
    internal void TestPlayback()
    {
        volume.Value = 0; grid.CurrentCell = grid.Rows[0].Cells[0]; Play();
        var mode = new StringBuilder(128);
        if (mciSendString($"status {alias} mode", mode, mode.Capacity, IntPtr.Zero) != 0 || mode.ToString() != "playing")
            throw new InvalidDataException("音频未进入播放状态。");
        Stop();
    }
    protected override void Dispose(bool disposing) { if (disposing) Stop(); base.Dispose(disposing); }
}
