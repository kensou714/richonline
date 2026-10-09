using System.Text.Json;

namespace RichOnline.Admin;

internal sealed record AdminLaunchSettings(string Server, string DataDirectory, string Client,
    string ClientConfig, ClientProfile Profile, bool StartServer = false)
{
    public static AdminLaunchSettings Load(string baseDirectory, string[] args)
    {
        baseDirectory = Path.GetFullPath(baseDirectory);
        var serverLayout = File.Exists(Path.Combine(baseDirectory, "RichOnline.Server.exe"));
        var clientDirectory = serverLayout ? Path.GetFullPath("..", baseDirectory) : baseDirectory;
        var values = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["server"] = serverLayout ? Path.Combine(baseDirectory, "RichOnline.Server.exe") : Path.Combine(baseDirectory, "server", "RichOnline.Server.exe"),
            ["data-dir"] = serverLayout ? Path.Combine(baseDirectory, "data") : Path.Combine(baseDirectory, "server", "data"),
            ["client"] = Path.Combine(clientDirectory, "RnClient.exe"),
            ["client-config"] = Path.Combine(clientDirectory, "local-server", "fixtures", "local.kpd"),
            ["client-profile"] = "richonline"
        };
        // 优先级为默认值、程序旁配置、命令行；配置内相对路径以管理器目录为基准。
        var configPath = Path.Combine(baseDirectory, "RichOnline.Admin.launch.json");
        if (File.Exists(configPath))
        {
            using var document = JsonDocument.Parse(File.ReadAllText(configPath));
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("启动配置必须为 JSON 对象：" + configPath);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!values.ContainsKey(property.Name) || !seen.Add(property.Name)
                    || property.Value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(property.Value.GetString()))
                    throw new InvalidDataException("启动配置存在未知、重复或空字段：" + property.Name + "；文件：" + configPath);
                var value = property.Value.GetString()!;
                values[property.Name] = property.Name == "client-profile" ? value : Path.GetFullPath(value, baseDirectory);
            }
        }
        var startServer = false;
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--start-server")
            {
                if (startServer) throw new ArgumentException("重复的启动参数：--start-server");
                startServer = true;
                continue;
            }
            if (args[i] == "--diagnostic-connect") continue;
            if (args[i] == "--render-diagnostics") { i++; continue; }
            var key = args[i].StartsWith("--", StringComparison.Ordinal) ? args[i][2..] : "";
            if (!values.ContainsKey(key) || i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                throw new ArgumentException("未知或缺少值的启动参数：" + args[i]);
            values[key] = key == "client-profile" ? args[++i] : Path.GetFullPath(args[++i]);
        }
        return new(values["server"], values["data-dir"], values["client"], values["client-config"],
            ClientProfiles.Parse(values["client-profile"]), startServer);
    }
}
