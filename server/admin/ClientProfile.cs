namespace RichOnline.Admin;

internal enum ClientProfile { Richonline, Original }

internal sealed record ServerLaunchOptions(string Executable, string DataDirectory,
    ClientProfile Profile = ClientProfile.Richonline, bool AdoptUntaggedProfile = false);

internal static class ClientProfiles
{
    public static string Argument(ClientProfile profile) => profile switch
    {
        ClientProfile.Richonline => "richonline",
        ClientProfile.Original => "original",
        _ => throw new ArgumentOutOfRangeException(nameof(profile))
    };
    public static ClientProfile Parse(string value) => value switch
    {
        "richonline" => ClientProfile.Richonline,
        "original" => ClientProfile.Original,
        _ => throw new ControlException("invalid_client_profile", "客户端版本必须为 richonline 或 original。")
    };
}
