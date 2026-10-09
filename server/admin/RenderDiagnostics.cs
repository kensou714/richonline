using System.Drawing.Imaging;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed partial class MainForm
{
    private void RenderDiagnostics(string outputDirectory)
    {
        var directory = Path.GetFullPath(outputDirectory);
        Directory.CreateDirectory(directory);
        var pages = new JsonArray();
        foreach (var size in new[] { new Size(1120, 780), new Size(900, 640) })
        {
            Size = size;
            for (var index = 0; index < tabs.TabPages.Count; index++)
            {
                tabs.SelectedIndex = index;
                tabs.Focus();
                PerformLayout(); tabs.PerformLayout(); tabs.SelectedTab?.PerformLayout();
                if (tabs.SelectedTab is { } page) page.AutoScrollPosition = Point.Empty;
                Refresh();
                var path = Path.Combine(directory, $"page-{index}-{size.Width}.png");
                using var bitmap = new Bitmap(Width, Height);
                DrawToBitmap(bitmap, new Rectangle(Point.Empty, Size));
                bitmap.Save(path, ImageFormat.Png);
                pages.Add(new JsonObject { ["page"] = tabs.TabPages[index].Text, ["width"] = Width,
                    ["height"] = Height, ["image"] = path, ["controls"] = DescribeControls(tabs.TabPages[index]) });
            }
        }
        File.WriteAllText(Path.Combine(directory, "layout-diagnostics.json"), new JsonObject
        {
            ["captureMethod"] = "WinForms Control.DrawToBitmap; not an OS screenshot or interactive QA",
            ["pages"] = pages
        }.ToJsonString(JsonFormatting.Indented));
        Close();
    }
    private static JsonArray DescribeControls(Control container)
    {
        var result = new JsonArray();
        foreach (Control control in container.Controls)
            result.Add(new JsonObject
            {
                ["type"] = control.GetType().Name, ["text"] = control is TextBox ? control.AccessibleName : control.Text,
                ["x"] = control.Left, ["y"] = control.Top, ["width"] = control.Width, ["height"] = control.Height,
                ["children"] = DescribeControls(control)
            });
        return result;
    }
}
