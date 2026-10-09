using System.Drawing.Drawing2D;

namespace RichOnline.Resources;

internal sealed class MapCanvas : Control
{
    public MapResource Map { get; }
    public int Selected { get; private set; } = -1;
    public event Action<int>? CellSelected;
    public float Zoom { get; set; } = 1;
    public MapCanvas(MapResource map)
    {
        Map = map; DoubleBuffered = true; BackColor = Color.FromArgb(242, 246, 250); Dock = DockStyle.Fill;
        MouseClick += (_, e) =>
        {
            var (size, ox, oy) = Geometry(); int x = (int)Math.Floor((e.X - ox) / size), y = (int)Math.Floor((e.Y - oy) / size);
            if (x < 0 || y < 0 || x >= Map.Width || y >= Map.Height) return;
            Selected = y * Map.Width + x; Invalidate(); CellSelected?.Invoke(Selected);
        };
    }
    private (float size, float x, float y) Geometry()
    {
        float size = Math.Max(1, Math.Min((Width - 40f) / Map.Width, (Height - 40f) / Map.Height)) * Zoom;
        return (size, (Width - size * Map.Width) / 2, (Height - size * Map.Height) / 2);
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e); var (size, ox, oy) = Geometry();
        using var road = new SolidBrush(Color.FromArgb(124, 169, 193)); using var linked = new SolidBrush(Color.FromArgb(222, 172, 93));
        using var empty = new SolidBrush(Color.FromArgb(225, 233, 239)); using var selected = new Pen(Ui.Accent, 3);
        for (int i = 0; i < Map.Width * Map.Height; i++)
        {
            float x = ox + i % Map.Width * size, y = oy + i / Map.Width * size;
            bool hasProperty = Map.Get(Map.Terrain + i * 64 + 56) >= 0;
            e.Graphics.FillRectangle(Map.Road(i) ? hasProperty ? linked : road : empty, x, y, Math.Max(1, size - 1), Math.Max(1, size - 1));
            if (i == Selected) e.Graphics.DrawRectangle(selected, x, y, size, size);
        }
    }
}

internal sealed class MapEditor : ResourceEditor
{
    private readonly MapResource map;
    private readonly MapCanvas canvas;
    private readonly FlowLayoutPanel detail = new() { Dock = DockStyle.Right, Width = 230, AutoScroll = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(8), BackColor = Color.White };
    public MapEditor(byte[] bytes)
    {
        map = MapResource.Load(bytes); canvas = new MapCanvas(map);
        Controls.Add(canvas); Controls.Add(detail);
        Controls.Add(Ui.Row(Ui.Label($"{map.Width} × {map.Height} 地块"), Ui.Label("蓝色：道路   金色：关联地产   灰色：非道路"), Ui.Button("开局设定", ShowDefaults)));
        canvas.CellSelected += ShowCell; ShowDefaults();
    }
    private void ClearDetail() { foreach (Control control in detail.Controls.Cast<Control>().ToArray()) control.Dispose(); detail.Controls.Clear(); }
    private void Number(string label, int offset, int minimum, int maximum)
    {
        int original = map.Get(offset);
        detail.Controls.Add(Ui.Label(label));
        var value = new NumericUpDown { Width = 185, Minimum = Math.Min(minimum, original), Maximum = Math.Max(maximum, original), Value = original, ThousandsSeparator = true };
        value.ValueChanged += (_, _) => { map.Set(offset, decimal.ToInt32(value.Value)); MarkChanged(); canvas.Invalidate(); };
        detail.Controls.Add(value);
    }
    private void ShowDefaults()
    {
        ClearDetail(); detail.Controls.Add(Ui.Label("开局设定"));
        Number("随身现金", map.Tail + 104, 0, int.MaxValue); Number("银行存款", map.Tail + 108, 0, int.MaxValue); Number("点券", map.Tail + 112, 0, int.MaxValue);
        Number("物价指数", map.Tail + 116, 0, 10000);
        detail.Controls.Add(new Label { Text = "点击地图查看地块与地产。\n这里显示道路结构，不是游戏场景渲染。", AutoSize = true, MaximumSize = new Size(190, 0), ForeColor = Ui.Muted, Margin = new Padding(8, 24, 0, 0) });
    }
    private void ShowCell(int cell)
    {
        ClearDetail(); detail.Controls.Add(Ui.Label($"地块 ({cell % map.Width}, {cell / map.Width})"));
        detail.Controls.Add(Ui.Label(map.Road(cell) ? "可通行道路" : "非道路地块"));
        if (!map.Road(cell)) return;
        detail.Controls.Add(Ui.Label("地块类别编号：" + map.Get(map.Types + cell * 4)));
        int x = map.Get(map.Terrain + cell * 64 + 56), y = map.Get(map.Terrain + cell * 64 + 60);
        if (x < 0 || y < 0 || x >= map.Width || y >= map.Height) { detail.Controls.Add(Ui.Label("未关联地产")); return; }
        detail.Controls.Add(Ui.Label($"关联地产 ({x}, {y})"));
        int property = map.Properties + (y * map.Width + x) * 88;
        Number("初始建筑等级", property + 16, 0, 5); Number("地价基数", property + 56, 0, int.MaxValue);
        detail.Controls.Add(new Label { Text = "实际地价还受全局物价设定影响。", AutoSize = true, MaximumSize = new Size(190, 0), ForeColor = Ui.Muted, Margin = new Padding(8) });
    }
    public override byte[] Build() => map.Save();
}
