using System.Diagnostics;

namespace RichOnline.Admin;

internal static class ClientLaunch
{
    public static ProcessStartInfo Prepare(string executable, string configuration, decimal area)
    {
        var path = Path.GetFullPath(executable);
        if (!File.Exists(path)) throw new FileNotFoundException("找不到选定的游戏客户端。", path);
        var config = Path.GetFullPath(configuration);
        if (!File.Exists(config)) throw new FileNotFoundException("找不到客户端 KPD 配置。请选择已验证的 local.kpd。", config);
        var directory = Path.GetDirectoryName(path)!;
        var argument = Path.GetRelativePath(directory, config);
        // 游戏客户端命令行不接受带引号的配置参数；保留原始字节，改传短 ASCII 相对路径。
        if (argument.Length >= 128 || argument.Any(character => character > 127 || char.IsWhiteSpace(character) || character == '"'))
        {
            var relativeDirectory = Path.Combine("richonline-admin-launch", Guid.NewGuid().ToString("N"));
            var ownedDirectory = Path.Combine(directory, relativeDirectory);
            Directory.CreateDirectory(ownedDirectory);
            argument = Path.Combine(relativeDirectory, "local.kpd");
            File.Copy(config, Path.Combine(directory, argument), overwrite: false);
        }
        // 资源按客户端工作目录查找；配置副本保留，供客户端启动后继续读取。
        var start = new ProcessStartInfo(path) { UseShellExecute = false, WorkingDirectory = directory };
        start.ArgumentList.Add(argument);
        start.ArgumentList.Add(area.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return start;
    }
}
