using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed class ControlException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

internal sealed class ControlClient(string pipeName)
{
    internal const int MaximumFrame = 65536;

    public async Task<JsonObject> SendAsync(string command, JsonObject? payload = null)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await pipe.ConnectAsync(timeout.Token);
        var requestId = Guid.NewGuid().ToString("N");
        var request = new JsonObject
        {
            ["version"] = 1, ["requestId"] = requestId, ["command"] = command,
            ["payload"] = payload ?? new JsonObject()
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(request);
        if (bytes.Length > MaximumFrame)
            throw new ControlException("request_too_large", "请求超过 64 KiB 限制。");
        // 管理管道使用四字节小端长度加 UTF-8 JSON，与游戏 TCP 帧格式相互独立。
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await pipe.WriteAsync(header, timeout.Token);
        await pipe.WriteAsync(bytes, timeout.Token);
        await pipe.FlushAsync(timeout.Token);
        await pipe.ReadExactlyAsync(header, timeout.Token);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length is 0 or > MaximumFrame)
            throw new ControlException("invalid_frame", "服务响应长度超出允许范围。");
        var body = new byte[length];
        await pipe.ReadExactlyAsync(body, timeout.Token);
        var response = JsonNode.Parse(body) as JsonObject
            ?? throw new ControlException("invalid_response", "服务响应必须是 JSON 对象。");
        // 一次连接承载一次请求；同时校验版本和关联标识，拒绝接受错配响应。
        if (response["version"]?.GetValue<int>() != 1 || response["requestId"]?.GetValue<string>() != requestId)
            throw new ControlException("response_mismatch", "服务响应版本或请求标识不匹配。");
        if (response["ok"]?.GetValue<bool>() != true)
        {
            var error = response["error"] as JsonObject;
            throw new ControlException(error?["code"]?.GetValue<string>() ?? "invalid_error",
                error?["message"]?.GetValue<string>() ?? "服务未返回错误说明。");
        }
        return response["result"] as JsonObject
            ?? throw new ControlException("invalid_result", "服务未返回结果对象。");
    }
}
