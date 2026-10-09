using System.Text.RegularExpressions;

namespace RichOnline.Resources;

internal sealed class TextRecord(string section, int start, int end)
{
    public string Section { get; } = section;
    public int Start { get; } = start;
    public int End { get; set; } = end;
    public Dictionary<string, int> Fields { get; } = new(StringComparer.OrdinalIgnoreCase);
}
internal sealed class TextTable
{
    public List<string> Lines { get; }
    public List<TextRecord> Records { get; } = [];
    private readonly string newline;
    public static readonly Dictionary<string, string> Labels = new(StringComparer.OrdinalIgnoreCase)
    {
        ["indx"]="编号", ["name"]="名称", ["string"]="显示文字", ["desc"]="说明", ["type"]="类别", ["enable"]="是否启用",
        ["sex"]="性别", ["mood"]="角色形象编号", ["enName"]="英文名", ["xingZuo"]="星座", ["birthday"]="生日", ["bloodType"]="血型", ["age"]="年龄",
        ["shengXiao"]="生肖", ["height"]="身高", ["weight"]="体重", ["work"]="职业", ["interest"]="兴趣", ["pet"]="宠物", ["favor"]="喜欢", ["dislike"]="讨厌",
        ["idol"]="偶像", ["language"]="语言", ["tag"]="口头禅", ["trait"]="性格", ["introduce"]="角色介绍", ["landFlag"]="地块旗帜图片",
        ["icon"]="图标编号", ["priceG"]="金豆价格", ["priceLJ"]="乐金价格", ["priceLR"]="乐券价格", ["saleG"]="允许金豆购买", ["saleLJ"]="允许乐金购买",
        ["saleLR"]="允许乐券购买", ["score"]="积分", ["fold"]="叠放数量", ["dayP"]="使用天数", ["yearJ"]="年限", ["dayJ"]="购买天数",
        ["src0"]="合成材料一", ["src1"]="合成材料二", ["src2"]="合成材料三", ["dest"]="合成结果", ["frame"]="动画帧数"
    };
    public TextTable(string text)
    {
        newline = text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        Lines = text.Split('\n').Select(l => l.TrimEnd('\r')).ToList();
        Parse();
    }
    private void Parse()
    {
        Records.Clear(); TextRecord? record = null;
        for (int i = 0; i < Lines.Count; i++)
        {
            var section = Regex.Match(Lines[i], @"^\s*\[([^\]]+)\]\s*$");
            if (section.Success)
            {
                if (record != null) record.End = i;
                record = new TextRecord(section.Groups[1].Value, i, Lines.Count); Records.Add(record);
            }
            else if (record != null)
            {
                var field = Regex.Match(Lines[i], @"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*[=:]");
                if (field.Success) record.Fields.TryAdd(field.Groups[1].Value, i);
            }
        }
    }
    public string Get(TextRecord record, string key)
    {
        if (!record.Fields.TryGetValue(key, out int index)) return "";
        string line = Lines[index]; int separator = line.IndexOfAny(['=', ':']); return line[(separator + 1)..].Trim();
    }
    public string Name(TextRecord r)
    {
        string label = Get(r, "name"); if (label.Length == 0) label = Get(r, "string");
        return label.Length == 0 ? r.Section : label;
    }
    public void Set(TextRecord record, string key, string value)
    {
        if (value.Contains('\n') || value.Contains('\r') || value.Contains('\0')) throw new InvalidDataException("一个字段只能填写一行，不能插入换行符。");
        if (key.Equals("indx", StringComparison.OrdinalIgnoreCase))
        {
            if (!int.TryParse(value, out int id) || id < 0 || id > 32767) throw new InvalidDataException("编号应在 0 到 32767 之间。");
            if (Records.Any(r => r != record && r.Section == record.Section && Get(r, "indx") == value)) throw new InvalidDataException("这个编号已被使用。");
        }
        if ((key.StartsWith("price", StringComparison.OrdinalIgnoreCase) || key is "fold" or "icon") && (!int.TryParse(value, out int number) || number < 0))
            throw new InvalidDataException("这里需要填写非负整数。");
        int line = record.Fields[key], separator = Lines[line].IndexOfAny(['=', ':']);
        Lines[line] = Lines[line][..(separator + 1)] + " " + value;
    }
    public void Duplicate(TextRecord record)
    {
        if (!record.Fields.ContainsKey("indx")) throw new InvalidDataException("这份设定不支持新增条目。");
        var used = Records.Select(r => Get(r, "indx")).ToHashSet(); int next = 0; while (used.Contains(next.ToString())) next++;
        if (next > 32767) throw new InvalidDataException("没有可用编号。");
        var copy = Lines.GetRange(record.Start, record.End - record.Start);
        int idLine = record.Fields["indx"] - record.Start;
        copy[idLine] = "indx = " + next;
        Lines.Add(""); Lines.AddRange(copy); Parse();
    }
    public void Delete(TextRecord record) { Lines.RemoveRange(record.Start, record.End - record.Start); Parse(); }
    public override string ToString() => string.Join(newline, Lines);
}
