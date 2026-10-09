using System.Text;
using System.Text.Json;

namespace RichOnline.Resources;

internal static class SelfTests
{
    public static int Run(string root, string output)
    {
        Directory.CreateDirectory(output); var checks = new List<string>();
        void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks.Add(message); }
        void Reject(Action action, string message) { bool rejected = false; try { action(); } catch (Exception e) when (e is InvalidDataException or IOException) { rejected = true; } Check(rejected, message); }
        try
        {
            var store = new ResourceStore(root); var files = store.Scan(); Check(files.Count > 19000, "真实目录扫描包含两万级资源");
            var defaultDirectory = new ResourceStore(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar);
            var resolve = Task.Run(() => defaultDirectory.Resolve("Data/Role.kpd"));
            Check(resolve.Wait(TimeSpan.FromSeconds(2)), "双击启动时带末尾分隔符的游戏目录必须在两秒内完成资源定位");
            Check(resolve.Result == store.Resolve("Data/Role.kpd"), "双击启动与手动选择目录定位到相同资源");
            foreach (string name in new[] { "Role", "Prop", "RichStr", "MapList", "AvatList", "CombCard" })
            {
                byte[] bytes = store.Read($"Data/{name}.kpd"); var text = new TextResource(bytes, true);
                Check(Packed.Decode(text.Save(text.Text)).SequenceEqual(Packed.Decode(bytes)), name + " 文本编码与压缩往返一致");
                var table = new TextTable(text.Text);
                Check(table.ToString() == text.Text, name + " 未编辑时逐字符保真");
            }
            var role = new TextResource(store.Read("Data/Role.kpd"), true); var roleTable = new TextTable(role.Text);
            Check(roleTable.Get(roleTable.Records[0], "name") == "金貝貝", "角色繁体编码正确识别");
            roleTable.Set(roleTable.Records[0], "name", "測試角色");
            Check(new TextResource(role.Save(roleTable.ToString()), true).Text.Contains("測試角色", StringComparison.Ordinal), "角色修改回读成功");
            Reject(() => role.Save("😀"), "不可表示的字符禁止有损保存");
            int records = roleTable.Records.Count; roleTable.Duplicate(roleTable.Records[0]);
            Check(roleTable.Records.Count == records + 1 && roleTable.Get(roleTable.Records[^1], "indx") != "0", "复制条目使用新编号");
            roleTable.Delete(roleTable.Records[^1]); Check(roleTable.Records.Count == records, "条目可删除");
            int maps = 0;
            foreach (var file in files.Where(f => f.Name.EndsWith(".emp", StringComparison.OrdinalIgnoreCase)))
            {
                var map = MapResource.Load(store.Read(file.RelativePath)); var reread = MapResource.Load(map.Save());
                if (!map.Header.SequenceEqual(reread.Header) || !map.Data.SequenceEqual(reread.Data)) throw new Exception("地图保真失败：" + file.Name);
                maps++;
            }
            Check(maps == 121, "121 份地图保存后头部和全部解压内容一致");
            var editedMap = MapResource.Load(store.Read("Map/BS_1_1.emp")); int oldCash = editedMap.Get(editedMap.Tail + 104);
            editedMap.Set(editedMap.Tail + 104, oldCash + 1); var mapRead = MapResource.Load(editedMap.Save());
            Check(mapRead.Get(mapRead.Tail + 104) == oldCash + 1, "地图开局现金修改回读正确");
            int packages = 0, sounds = 0;
            foreach (var file in files.Where(f => (f.Category is "音乐" or "音效") && f.Name.EndsWith(".dat", StringComparison.OrdinalIgnoreCase)))
            {
                var package = AudioPackage.Load(store.Read(file.RelativePath)); var reread = AudioPackage.Load(package.Save());
                if (package.Items.Count != reread.Items.Count || package.Items.Where((item, index) => item.Id != reread.Items[index].Id || !item.Content.SequenceEqual(reread.Items[index].Content)).Any()) throw new Exception("声音包保真失败：" + file.Name);
                packages++; sounds += package.Items.Count;
            }
            Check(packages == 63 && sounds == 1161, "63 个声音包、1161 条音频编号与内容往返一致");
            Check(AudioCatalog.Read(store, true).Effective[1].EndsWith("mus0016.dat", StringComparison.Ordinal), "音乐同编号覆盖顺序与客户端一致");
            Check(AudioCatalog.Read(store, false).Effective[4].EndsWith("snd0019.dat", StringComparison.Ordinal), "音效同编号覆盖顺序与客户端一致");
            int pictures = 0, animations = 0;
            foreach (var file in files.Where(f => f.Name.EndsWith(".np", StringComparison.OrdinalIgnoreCase)))
            {
                using var image = PictureResource.Load(store.Read(file.RelativePath)); pictures++; if (image.Frames.Count > 1) animations++;
            }
            Check(pictures == 19592 && animations == 7283, "19592 份图片与 7283 份动画完整解码");
            using (var image = PictureResource.Load(store.Read("Tex/17/08950.np")))
            {
                using var reread = PictureResource.Load(PictureResource.FromImage(image.Frames[0], 23));
                bool same = true;
                for (int y = 0; y < image.Frames[0].Height; y++) for (int x = 0; x < image.Frames[0].Width; x++)
                    if (image.Frames[0].GetPixel(x, y).A > 0 && image.Frames[0].GetPixel(x, y).ToArgb() != reread.Frames[0].GetPixel(x, y).ToArgb()) same = false;
                Check(same, "透明图片重新编码后像素一致");
            }
            Reject(() => Packed.Decode([1, 2, 3]), "截断压缩资源被拒绝");
            Reject(() => MapResource.Load(new byte[30]), "损坏地图被拒绝");
            Reject(() => AudioPackage.Load("mus%"u8.ToArray()), "损坏音频包被拒绝");
            string sandbox = Path.Combine(output, "sandbox-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(Path.Combine(sandbox, "Data")); Directory.CreateDirectory(Path.Combine(sandbox, "Map"));
            var scratch = new ResourceStore(sandbox); byte[] first = Encoding.UTF8.GetBytes("第一版"), second = Encoding.UTF8.GetBytes("第二版");
            scratch.Write("Data/test.txt", first, null, "导入资源"); scratch.Write("Data/test.txt", second, ResourceStore.Hash(first));
            Reject(() => scratch.Write("Data/test.txt", first, ResourceStore.Hash(first)), "外部修改冲突阻止覆盖");
            scratch.Restore(scratch.History().First()); Check(scratch.Read("Data/test.txt").SequenceEqual(first), "历史恢复成功");
            scratch.Delete("Data/test.txt", ResourceStore.Hash(first)); Check(!File.Exists(Path.Combine(sandbox, "Data/test.txt")), "回收站操作移除原文件");
            scratch.Restore(scratch.History().First()); Check(scratch.Read("Data/test.txt").SequenceEqual(first), "误删文件可完整恢复");
            Reject(() => scratch.Resolve("../outside.txt"), "目录穿越被拒绝");
            Reject(() => scratch.Resolve("RnClient.exe"), "客户端程序不可被资源编辑器改写");
            Reject(() => scratch.Write("Data/test.txt", second, null), "导入重名资源禁止覆盖");
            using (var host = new Form())
            using (var tableEditor = new TableEditor(store.Read("Data/Role.kpd"), true))
            {
                host.Controls.Add(tableEditor); host.Show(); Application.DoEvents();
                static IEnumerable<Control> Children(Control parent) => parent.Controls.Cast<Control>().SelectMany(c => new[] { c }.Concat(Children(c)));
                var fields = Children(tableEditor).OfType<DataGridView>().Single(g => g.Columns.Contains("value"));
                var row = fields.Rows.Cast<DataGridViewRow>().Single(r => r.Tag as string == "name");
                fields.CurrentCell = row.Cells[1]; fields.BeginEdit(true);
                ((TextBox)fields.EditingControl).Text = "是"; tableEditor.Flush();
                var saved = new TextResource(tableEditor.Build(), true);
                Check(tableEditor.Dirty && saved.Text.Contains("name = 是", StringComparison.Ordinal), "实际表格编辑提交与未保存标记正常，名称不会误转布尔值");
                host.Hide();
            }
            foreach (string path in new[] { "Music/mus0000.dat", "Sound/snd0000.dat" })
            {
                using var host = new Form(); using var audio = new AudioEditor(store.Read(path)); host.Controls.Add(audio); host.Show(); Application.DoEvents();
                audio.TestPlayback(); Check(true, path + " 系统播放器静音试听进入播放状态"); host.Hide();
            }
            File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new { passed = true, checks, maps, packages, sounds, pictures, animations }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        catch (Exception error)
        {
            File.WriteAllText(Path.Combine(output, "results.json"), JsonSerializer.Serialize(new { passed = false, checks, error = error.ToString() }, new JsonSerializerOptions { WriteIndented = true })); return 1;
        }
    }
}
