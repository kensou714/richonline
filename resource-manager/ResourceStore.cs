using System.Security.Cryptography;
using System.Text.Json;

namespace RichOnline.Resources;

internal sealed record ResourceFile(string RelativePath, string Category, long Size, DateTime Modified)
{
    public string Name => Path.GetFileName(RelativePath);
    public string DisplayName => ResourceStore.DisplayName(RelativePath);
}
internal sealed record Revision(string Id, string Path, string Action, DateTime Time, string? Blob, string? ResultHash);
internal sealed class ResourceStore
{
    public static readonly string[] Folders = ["Map", "Music", "Sound", "Avatar", "Data", "Tex", "Interface", "SysRes", "Font", "Config"];
    public static readonly string[] Categories = ["全部资源", "地图", "音乐", "音效", "角色", "道具卡", "文本", "图片与动画", "界面", "其他设定"];
    private static readonly Dictionary<string, string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Role"] = "角色设定", ["Prop"] = "道具与卡片", ["RichStr"] = "游戏文字", ["CombCard"] = "卡片合成", ["SellProp"] = "商店出售列表",
        ["AvatList"] = "角色服装", ["Npc"] = "神仙与 NPC", ["VoiceFace"] = "语音与表情", ["MapList"] = "地图开放列表", ["MapView"] = "地图介绍",
        ["BossWar"] = "BOSS 关卡", ["BossWar_v"] = "特殊 BOSS 关卡", ["Option"] = "游戏基础设定", ["GValue"] = "游戏数值", ["Level"] = "等级与经验",
        ["Build"] = "建筑设定", ["Stock"] = "股票设定", ["BwNews"] = "游戏新闻", ["Help"] = "帮助文字", ["LogFixStr"] = "记录用语", ["Pawn"] = "典当设定"
    };
    public static string DisplayName(string relative)
    {
        string name = Path.GetFileNameWithoutExtension(relative);
        if (relative.Replace('\\', '/').StartsWith("Data/", StringComparison.OrdinalIgnoreCase) && Names.TryGetValue(name, out var label)) return label;
        if (name.StartsWith("mus", StringComparison.OrdinalIgnoreCase) && int.TryParse(name[3..], out int music)) return "音乐包 " + music.ToString("D2");
        if (name.StartsWith("snd", StringComparison.OrdinalIgnoreCase) && int.TryParse(name[3..], out int sound)) return "音效包 " + sound.ToString("D2");
        if (Path.GetExtension(relative).Equals(".np", StringComparison.OrdinalIgnoreCase)) return Path.GetFileName(Path.GetDirectoryName(relative)) + " / " + Path.GetFileName(relative);
        return Path.GetFileName(relative);
    }
    public string Root { get; }
    private string HistoryRoot => Path.Combine(Root, ".resource-workbench", "history");
    public ResourceStore(string root)
    {
        Root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (!Directory.Exists(Path.Combine(Root, "Data")) || !Directory.Exists(Path.Combine(Root, "Map")))
            throw new InvalidDataException("请选择包含 Data 和 Map 文件夹的游戏目录。");
    }
    public static string Category(string relative)
    {
        string folder = relative.Replace('\\', '/').Split('/')[0].ToLowerInvariant(), name = Path.GetFileNameWithoutExtension(relative).ToLowerInvariant();
        return folder switch
        {
            "map" => "地图", "music" => "音乐", "sound" => "音效", "avatar" => "角色", "tex" => "图片与动画", "interface" => "界面",
            "data" when name is "role" or "avatlist" or "npc" or "facectrl" or "voiceface" => "角色",
            "data" when name is "prop" or "combcard" or "sellprop" or "newprops" or "rafflecard" => "道具卡",
            "data" when name is "richstr" or "logfixstr" or "help" or "bwnews" or "konews" or "filter" or "filtern" => "文本",
            _ => "其他设定"
        };
    }
    public string Resolve(string relative)
    {
        if (Path.IsPathRooted(relative) || relative.Contains(':')) throw new InvalidDataException("资源位置不正确。");
        string full = Path.GetFullPath(Path.Combine(Root, relative));
        if (!full.StartsWith(Root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("只能操作当前游戏目录内的资源。");
        string rel = Path.GetRelativePath(Root, full);
        if (!Folders.Contains(rel.Split(Path.DirectorySeparatorChar)[0], StringComparer.OrdinalIgnoreCase) || rel.Split(Path.DirectorySeparatorChar).Length < 2)
            throw new InvalidDataException("此位置不是资源目录。");
        for (string? current = full; !string.Equals(current, Root, StringComparison.OrdinalIgnoreCase); current = Path.GetDirectoryName(current))
        {
            if (current == null) throw new InvalidDataException("资源位置不在当前游戏目录中。");
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("请直接打开真实资源目录，不能通过目录链接写入。");
        }
        return full;
    }
    public List<ResourceFile> Scan()
    {
        var files = new List<ResourceFile>();
        var options = new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = false };
        foreach (string folder in Folders)
        {
            string path = Path.Combine(Root, folder); if (!Directory.Exists(path)) continue;
            foreach (var file in new DirectoryInfo(path).EnumerateFiles("*", options))
            {
                if (file.Extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || file.Extension.Equals(".asi", StringComparison.OrdinalIgnoreCase) || file.Extension.Equals(".m3d", StringComparison.OrdinalIgnoreCase)) continue;
                string relative = Path.GetRelativePath(Root, file.FullName);
                files.Add(new(relative, Category(relative), file.Length, file.LastWriteTime));
            }
        }
        return files.OrderBy(f => f.DisplayName == f.Name ? 1 : 0).ThenBy(f => f.RelativePath, StringComparer.OrdinalIgnoreCase).ToList();
    }
    public static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    public byte[] Read(string relative) => Packed.ReadFile(Resolve(relative));
    private Revision Record(string relative, string action, byte[]? before, byte[]? after)
    {
        Directory.CreateDirectory(HistoryRoot);
        string id = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff") + "-" + Guid.NewGuid().ToString("N");
        string? blob = before == null ? null : id + ".bin";
        if (blob != null) File.WriteAllBytes(Path.Combine(HistoryRoot, blob), before!);
        var revision = new Revision(id, relative, action, DateTime.Now, blob, after == null ? null : Hash(after));
        File.WriteAllText(Path.Combine(HistoryRoot, id + ".json"), JsonSerializer.Serialize(revision));
        return revision;
    }
    public void Write(string relative, byte[] content, string? expectedHash, string action = "保存")
    {
        string path = Resolve(relative);
        byte[]? before = File.Exists(path) ? Packed.ReadFile(path) : null;
        if ((before == null ? null : Hash(before)) != expectedHash) throw new IOException("文件已被其他操作修改，请重新打开后再保存。");
        Record(relative, action, before, content);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temp, content);
            if (before == null) File.Move(temp, path);
            else
            {
                if (Hash(Packed.ReadFile(path)) != expectedHash) throw new IOException("文件刚刚发生变化，请重新打开。");
                File.Replace(temp, path, null);
            }
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public void Delete(string relative, string expectedHash)
    {
        string path = Resolve(relative); byte[] before = Packed.ReadFile(path);
        if (Hash(before) != expectedHash) throw new IOException("文件已发生变化，请刷新后重试。");
        Record(relative, "移入回收站", before, null); File.Delete(path);
    }
    public List<Revision> History() => !Directory.Exists(HistoryRoot) ? [] : Directory.GetFiles(HistoryRoot, "*.json")
        .Select(p => JsonSerializer.Deserialize<Revision>(File.ReadAllText(p)) ?? throw new InvalidDataException("历史记录无法读取。"))
        .OrderByDescending(r => r.Time).ToList();
    public void Restore(Revision revision)
    {
        if (revision.Blob == null) throw new InvalidDataException("这条记录是首次导入，没有更早版本。");
        if (Path.GetFileName(revision.Blob) != revision.Blob) throw new InvalidDataException("历史记录位置不正确。");
        string path = Resolve(revision.Path);
        var current = File.Exists(path) ? Read(revision.Path) : null;
        if ((current == null ? null : Hash(current)) != revision.ResultHash) throw new IOException("资源后来又有修改。请先导出当前文件，再从历史中选择最近一次记录恢复。");
        Write(revision.Path, File.ReadAllBytes(Path.Combine(HistoryRoot, revision.Blob)), current == null ? null : Hash(current), "恢复历史版本");
    }
}
