namespace RichOnline.Admin;

internal sealed partial class MainForm
{
    private readonly Label clientActionResult = new() { AutoSize = true, Text = "客户端：尚未执行结束操作" };
    private Button? endClientButton;

    private async Task EndClientAsync()
    {
        var target = new ClientStopTarget(clientPath.Text, serverPath.Text, server.Pid);
        clientActionResult.Text = "客户端：正在请求正常关闭，超时后强制结束…";
        try
        {
            var result = await ClientStop.StopAsync(target, QueueLog);
            clientActionResult.Text = result.Matched == 0
                ? result.Unverified > 0 ? "客户端：路径无法确认，已跳过；请查看日志" : "客户端：配置路径的进程未运行"
                : $"客户端：匹配 {result.Matched}，正常结束 {result.Closed}，强制结束 {result.Forced}，失败 {result.Failed}";
        }
        catch { clientActionResult.Text = "客户端：结束操作失败，请查看日志"; throw; }
    }
}
