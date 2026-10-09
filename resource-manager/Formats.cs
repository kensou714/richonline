using System.Buffers.Binary;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;

namespace RichOnline.Resources;

internal static class Packed
{
    public const int Limit = 64 * 1024 * 1024;
    [DllImport("ResourceCodec.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int resource_decompress(byte[] source, nuint length, byte[] target, nuint capacity);
    [DllImport("ResourceCodec.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int resource_compress(byte[] source, nuint length, byte[] target, nuint capacity, out nuint actual);
    public static int Int(byte[] data, int offset)
    {
        if (offset < 0 || offset > data.Length - 4) throw new InvalidDataException("资源内容不完整。");
        return BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
    }
    public static void Put(byte[] data, int offset, int value) => BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(offset, 4), value);
    public static byte[] ReadFile(string path)
    {
        if (new FileInfo(path).Length > Limit * 2) throw new InvalidDataException("文件超过支持的大小（128 MB）。");
        return File.ReadAllBytes(path);
    }
    public static byte[] Decode(byte[] data)
    {
        if (data.Length < 9 || data.Length > Limit * 2) throw new InvalidDataException("不是支持的资源文件。");
        byte[] shifted = data[1..];
        for (int i = 0; i < shifted.Length; i++) shifted[i] = unchecked((byte)(shifted[i] - data[0]));
        int size = Int(shifted, 0), count = Int(shifted, 4);
        if (size <= 0 || size > Limit || count != shifted.Length - 8) throw new InvalidDataException("资源大小校验未通过。");
        return Decompress(shifted[8..], size);
    }
    public static byte[] Decompress(byte[] bytes, int size)
    {
        if (size <= 0 || size > Limit) throw new InvalidDataException("解压大小超出范围。");
        var output = new byte[size];
        if (resource_decompress(bytes, (nuint)bytes.Length, output, (nuint)size) != 0) throw new InvalidDataException("资源解压失败，文件可能已损坏。");
        return output;
    }
    public static byte[] Encode(byte[] bytes, byte key)
    {
        if (bytes.Length == 0 || bytes.Length > Limit) throw new InvalidDataException("资源内容为空或过大。");
        var compressed = new byte[bytes.Length + bytes.Length / 16 + 67];
        if (resource_compress(bytes, (nuint)bytes.Length, compressed, (nuint)compressed.Length, out var actual) != 0)
            throw new InvalidDataException("资源保存准备失败。");
        var result = new byte[(int)actual + 9]; result[0] = key;
        Put(result, 1, bytes.Length); Put(result, 5, (int)actual);
        compressed.AsSpan(0, (int)actual).CopyTo(result.AsSpan(9));
        for (int i = 1; i < result.Length; i++) result[i] = unchecked((byte)(result[i] + key));
        if (!Decode(result).AsSpan().SequenceEqual(bytes)) throw new InvalidDataException("资源回读校验失败。");
        return result;
    }
}

internal sealed class PictureResource : IDisposable
{
    public List<Bitmap> Frames { get; } = [];
    public List<int> Durations { get; } = [];
    public static PictureResource Load(byte[] packed)
    {
        var data = Packed.Decode(packed); int width = Packed.Int(data, 1), height = Packed.Int(data, 5);
        if (width <= 0 || height <= 0 || (long)width * height > 1024 * 1024) throw new InvalidDataException("图片尺寸不受支持。");
        int pixels = width * height, mode = data[0], frames = mode == 1 ? Packed.Int(data, 9) : 1;
        if (mode is not (1 or 2) || frames < 1 || frames > 256 || (long)pixels * frames > 16 * 1024 * 1024)
            throw new InvalidDataException("图片帧数或格式不受支持。");
        bool alpha = mode == 1 && data[13] != 0;
        if (alpha && frames > 1) throw new InvalidDataException("此透明动画需要进一步确认格式，暂不能预览或改写。");
        int cursor = mode == 1 ? 14 : 9;
        var result = new PictureResource();
        try
        {
            for (int f = 0; f < frames; f++)
            {
                int required = mode == 1 ? 768 + pixels * (alpha ? 2 : 1) : pixels * 4;
                if (cursor > data.Length - required) throw new InvalidDataException("图片帧内容不完整。");
                var bgra = new byte[pixels * 4];
                for (int p = 0; p < pixels; p++)
                {
                    if (mode == 2) Array.Copy(data, cursor + p * 4, bgra, p * 4, 4);
                    else
                    {
                        int color = cursor + data[cursor + 768 + p] * 3;
                        byte r = data[color], g = data[color + 1], b = data[color + 2];
                        bgra[p * 4] = b; bgra[p * 4 + 1] = g; bgra[p * 4 + 2] = r;
                        bgra[p * 4 + 3] = r == 0 && g == 255 && b == 0 ? (byte)0 : alpha ? data[cursor + 768 + pixels + p] : (byte)255;
                    }
                }
                var bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb);
                var bits = bitmap.LockBits(new Rectangle(0, 0, width, height), ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);
                try { Marshal.Copy(bgra, 0, bits.Scan0, bgra.Length); } finally { bitmap.UnlockBits(bits); }
                result.Frames.Add(bitmap); cursor += required;
            }
            for (int f = 0; f < frames; f++) result.Durations.Add(frames > 1 ? Math.Clamp(Packed.Int(data, cursor + f * 4), 1, 60000) : 100);
            return result;
        }
        catch { result.Dispose(); throw; }
    }
    public static byte[] FromImage(Bitmap bitmap, byte key)
    {
        if (bitmap.Width > 1024 || bitmap.Height > 1024) throw new InvalidDataException("图片最长边不能超过 1024 像素。");
        using var copy = bitmap.Clone(new Rectangle(0, 0, bitmap.Width, bitmap.Height), PixelFormat.Format32bppArgb);
        var bytes = new byte[9 + copy.Width * copy.Height * 4]; bytes[0] = 2;
        Packed.Put(bytes, 1, copy.Width); Packed.Put(bytes, 5, copy.Height);
        var bits = copy.LockBits(new Rectangle(0, 0, copy.Width, copy.Height), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
        try { Marshal.Copy(bits.Scan0, bytes, 9, bytes.Length - 9); } finally { copy.UnlockBits(bits); }
        return Packed.Encode(bytes, key);
    }
    public void Dispose() { foreach (var bitmap in Frames) bitmap.Dispose(); Frames.Clear(); }
}

internal sealed record AudioItem(int Id, byte[] Content, int Extra = 0);
internal sealed class AudioPackage
{
    public byte[] Header { get; private init; } = [];
    public List<AudioItem> Items { get; } = [];
    public bool Music => Header[0] == (byte)'m';
    public static AudioPackage Load(byte[] data)
    {
        if (data.Length < 12 || !(data.AsSpan(0, 4).SequenceEqual("mus%"u8) || data.AsSpan(0, 4).SequenceEqual("snd%"u8)))
            throw new InvalidDataException("不是音乐或音效资源包。");
        int count = Packed.Int(data, 8);
        if (count < 1 || count > 20000 || 12L + count * 16L > data.Length) throw new InvalidDataException("声音目录不完整。");
        var result = new AudioPackage { Header = data[..12] };
        for (int i = 0; i < count; i++)
        {
            int at = 12 + i * 16, id = Packed.Int(data, at), offset = Packed.Int(data, at + 4), size = Packed.Int(data, at + 8), extra = Packed.Int(data, at + 12);
            int packedSize = !result.Music && extra != 0 ? extra : size;
            if (id < 0 || id > 1000000 || size < 1 || size > Packed.Limit || offset < 12 + count * 16 || packedSize < 1 || (long)offset + packedSize > data.Length)
                throw new InvalidDataException("声音内容超出文件范围。");
            var content = data[offset..(offset + packedSize)];
            if (!result.Music && extra != 0) content = Packed.Decompress(content, size);
            result.Items.Add(new AudioItem(id, content, result.Music ? extra : 0));
        }
        return result;
    }
    public byte[] Save()
    {
        if (Items.Count == 0) throw new InvalidDataException("资源包至少保留一条声音。");
        long total = 12L + Items.Count * 16L + Items.Sum(i => (long)i.Content.Length);
        if (total > Packed.Limit * 2) throw new InvalidDataException("资源包过大。");
        byte[] data = new byte[(int)total]; Header.CopyTo(data, 0); Packed.Put(data, 8, Items.Count);
        int cursor = 12 + Items.Count * 16;
        for (int i = 0; i < Items.Count; i++)
        {
            var item = Items[i]; int at = 12 + i * 16;
            Packed.Put(data, at, item.Id); Packed.Put(data, at + 4, cursor); Packed.Put(data, at + 8, item.Content.Length); Packed.Put(data, at + 12, item.Extra);
            item.Content.CopyTo(data, cursor); cursor += item.Content.Length;
        }
        _ = Load(data); return data;
    }
    public static string Extension(byte[] data) => data.AsSpan().StartsWith("RIFF"u8) ? ".wav" : ".mp3";
    public static void ValidateReplacement(byte[] old, byte[] replacement)
    {
        bool wave = old.AsSpan().StartsWith("RIFF"u8);
        bool valid = wave ? replacement.Length >= 12 && replacement.AsSpan(0, 4).SequenceEqual("RIFF"u8) && replacement.AsSpan(8, 4).SequenceEqual("WAVE"u8)
            : replacement.Length > 3 && (replacement.AsSpan().StartsWith("ID3"u8) || (replacement[0] == 255 && (replacement[1] & 224) == 224));
        if (!valid) throw new InvalidDataException(wave ? "请选用 WAV 声音文件。" : "请选用 MP3 音乐文件。");
    }
}

internal sealed class MapResource
{
    public byte[] Header { get; private init; } = [];
    public byte[] Data { get; private init; } = [];
    public byte Key { get; private init; }
    public int Width { get; private init; }
    public int Height { get; private init; }
    public int Terrain { get; private init; }
    public int Types { get; private init; }
    public int Properties { get; private init; }
    public int Tail { get; private init; }
    public static MapResource Load(byte[] file)
    {
        int version = Packed.Int(file, 16);
        if (version < 1 || version > 3) throw new InvalidDataException("暂不支持这份地图的版本。");
        int metadata = 3 + (version >= 2 ? 2 : 0) + (version >= 3 ? 1 : 0), block = 23288 + metadata * 4 + 120;
        int width = Packed.Int(file, 23288 + (metadata - 2) * 4), height = Packed.Int(file, 23288 + (metadata - 1) * 4);
        if (width <= 0 || height <= 0 || (long)width * height > 32768 || block >= file.Length) throw new InvalidDataException("地图尺寸或内容不正确。");
        var data = Packed.Decode(file[block..]); int bw = Packed.Int(data, 8), bh = Packed.Int(data, 12);
        long terrain = 16L + (long)bw * bh * 4, endTerrain = terrain + (long)width * height * 64;
        if (bw <= 0 || bh <= 0 || terrain > data.Length || endTerrain > data.Length - 4) throw new InvalidDataException("地图地形不完整。");
        int decorations = Packed.Int(data, (int)endTerrain);
        long types = endTerrain + 4 + (long)decorations * 36, properties = types + (long)width * height * 4, tail = properties + (long)width * height * 88;
        if (decorations < 0 || tail > data.Length - 120) throw new InvalidDataException("地图建筑或设定不完整。");
        return new MapResource { Header = file[..block], Key = file[block], Data = data, Width = width, Height = height,
            Terrain = (int)terrain, Types = (int)types, Properties = (int)properties, Tail = (int)tail };
    }
    public bool Road(int cell) => (Get(Terrain + cell * 64) & 255) != 255;
    public int Get(int offset) => Packed.Int(Data, offset);
    public void Set(int offset, int value) => Packed.Put(Data, offset, value);
    public byte[] Save()
    {
        var result = Header.Concat(Packed.Encode(Data, Key)).ToArray(); _ = Load(result); return result;
    }
}

internal sealed class TextResource
{
    public byte[] Original { get; }
    public Encoding Encoding { get; }
    public string Text { get; }
    public bool Compressed { get; }
    private readonly byte[] preamble;
    public TextResource(byte[] original, bool compressed)
    {
        Original = original; Compressed = compressed;
        byte[] bytes = compressed ? Packed.Decode(original) : original;
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        if (bytes.AsSpan().StartsWith(new byte[] { 239, 187, 191 })) { preamble = bytes[..3]; Encoding = new UTF8Encoding(false, true); }
        else if (bytes.AsSpan().StartsWith(new byte[] { 255, 254 })) { preamble = bytes[..2]; Encoding = new UnicodeEncoding(false, false, true); }
        else
        {
            preamble = [];
            try { _ = new UTF8Encoding(false, true).GetString(bytes); Encoding = new UTF8Encoding(false, true); }
            catch (DecoderFallbackException) { Encoding = Encoding.GetEncoding(950, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback); }
        }
        Text = Encoding.GetString(bytes, preamble.Length, bytes.Length - preamble.Length);
        if (Text.Contains('\0')) throw new InvalidDataException("这份资源不是可编辑文本。");
    }
    public byte[] Save(string text)
    {
        byte[] encoded;
        try { encoded = preamble.Concat(Encoding.GetBytes(text)).ToArray(); }
        catch (EncoderFallbackException) { throw new InvalidDataException("有文字无法存入游戏使用的字库编码，请改用繁体字或现有游戏字符。"); }
        return Compressed ? Packed.Encode(encoded, Original[0]) : encoded;
    }
}
