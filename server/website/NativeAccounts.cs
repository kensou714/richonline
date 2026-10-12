using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RichOnline.Website;

internal sealed class AccountError(string code) : Exception(code);

internal sealed class NativeAccounts(string pipeName)
{
    private readonly SemaphoreSlim queue = new(1);
    // 公网请求只能使用固定账号命令，不能传入任意管理命令或 SQL。
    public async Task<JsonObject> Send(string action, JsonObject payload, CancellationToken abort)
    {
        if (action is not ("register" or "account" or "password" or "claim")) throw new AccountError("invalid_request");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(abort);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        if (!await queue.WaitAsync(TimeSpan.FromSeconds(1), deadline.Token)) throw new AccountError("busy");
        try
        {
            await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(deadline.Token);
            var id = Guid.NewGuid().ToString("N");
            var bytes = JsonSerializer.SerializeToUtf8Bytes(new JsonObject
            {
                ["version"] = 1, ["requestId"] = id, ["command"] = "website." + action, ["payload"] = payload
            });
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
            await pipe.WriteAsync(header, deadline.Token);
            await pipe.WriteAsync(bytes, deadline.Token);
            await pipe.FlushAsync(deadline.Token);
            await pipe.ReadExactlyAsync(header, deadline.Token);
            var length = BinaryPrimitives.ReadInt32LittleEndian(header);
            if (length is < 1 or > 65536) throw new AccountError("service_unavailable");
            var body = new byte[length];
            await pipe.ReadExactlyAsync(body, deadline.Token);
            var response = JsonNode.Parse(body) as JsonObject;
            if (response?["version"]?.GetValue<int>() != 1 || response["requestId"]?.GetValue<string>() != id)
                throw new AccountError("service_unavailable");
            if (response["ok"]?.GetValue<bool>() != true)
                throw new AccountError(response["error"]?["code"]?.GetValue<string>() ?? "service_unavailable");
            return response["result"] as JsonObject ?? throw new AccountError("service_unavailable");
        }
        finally { queue.Release(); }
    }
}
