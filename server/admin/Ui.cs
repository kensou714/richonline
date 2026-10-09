namespace RichOnline.Admin;

internal static class Ui
{
    public const int Gap = 8;
    public const int PagePadding = 16;
    public static Button Button(string text, EventHandler action)
    {
        var button = new Button { Text = text, AutoSize = true, Padding = new Padding(Gap, 3, Gap, 3) };
        button.Click += action;
        return button;
    }
    public static FlowLayoutPanel Row(params Control[] controls)
    {
        var row = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true,
            Padding = new Padding(0, Gap, 0, Gap) };
        row.Controls.AddRange(controls);
        return row;
    }
    public static TextBox Text(string accessibleName, bool multiline = false) => new()
    {
        AccessibleName = accessibleName, Dock = DockStyle.Fill, Multiline = multiline,
        ScrollBars = multiline ? ScrollBars.Both : ScrollBars.None,
        WordWrap = !multiline
    };
    public static TableLayoutPanel Fields() => new()
    {
        Dock = DockStyle.Top, AutoSize = true, ColumnCount = 2,
        ColumnStyles = { new ColumnStyle(SizeType.Absolute, 130), new ColumnStyle(SizeType.Percent, 100) }
    };
    public static void Field(TableLayoutPanel table, string label, Control input)
    {
        var row = table.RowCount++;
        table.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        table.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left,
            Margin = new Padding(0, Gap, Gap, Gap) }, 0, row);
        input.Margin = new Padding(0, 4, 0, 4);
        table.Controls.Add(input, 1, row);
    }
    public static TabPage Page(string name) => new(name) { Padding = new Padding(PagePadding) };
}
