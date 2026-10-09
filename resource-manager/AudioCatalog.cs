namespace RichOnline.Resources;

internal sealed class AudioCatalog
{
    public Dictionary<int, string> Effective { get; } = [];
    public HashSet<string> Loaded { get; } = new(StringComparer.OrdinalIgnoreCase);
    public static AudioCatalog Read(ResourceStore store, bool music)
    {
        var result = new AudioCatalog(); string directory = music ? "Music" : "Sound", prefix = music ? "mus" : "snd";
        int? batch = null;
        for (int number = 0; number < 10000; number++)
        {
            string relative = Path.Combine(directory, prefix + number.ToString("D4") + ".dat"), path = store.Resolve(relative);
            if (!File.Exists(path)) break;
            using var stream = File.OpenRead(path);
            byte[] header = new byte[12]; stream.ReadExactly(header);
            int value = Packed.Int(header, 4), count = Packed.Int(header, 8); batch ??= value;
            if (value != batch || count == 0) continue;
            if (count < 0 || count > 20000 || 12L + count * 16L > stream.Length) throw new InvalidDataException("声音目录不完整：" + relative);
            byte[] index = new byte[count * 16]; stream.ReadExactly(index); result.Loaded.Add(relative);
            for (int i = 0; i < count; i++) result.Effective[Packed.Int(index, i * 16)] = relative;
        }
        return result;
    }
    public string State(string relative, int id)
    {
        if (!Loaded.Contains(relative)) return "此包尚未被游戏收录";
        return Effective.TryGetValue(id, out var winner) && !winner.Equals(relative, StringComparison.OrdinalIgnoreCase)
            ? "已被" + ResourceStore.DisplayName(winner) + "覆盖" : "当前生效";
    }
}
