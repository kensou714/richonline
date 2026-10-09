using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed class ServerProcess : IDisposable
{
    private Process? process;
    private OwnedJob? job;
    private Task? stdoutTask;
    private Task? stderrTask;
    private TaskCompletionSource<JsonObject>? ready;
    private bool stopping;
    private string? startupFailureReason;
    public event Action<string, string>? Log;
    public event Action? Exited;
    public ControlClient? Control { get; private set; }
    public bool IsAlive => process is { HasExited: false };
    public int? Pid => IsAlive ? process?.Id : null;

    public async Task<JsonObject> StartAsync(ServerLaunchOptions options)
    {
        if (IsAlive) throw new ControlException("already_running", "当前管理器已拥有一个运行中的服务。");
        DisposeProcess();
        var fullPath = Path.GetFullPath(options.Executable);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("未找到 C++ 服务端。请选择已构建的 RichOnline.Server.exe。", fullPath);
        var pipeName = $"richonline-admin-{Environment.ProcessId}-{Guid.NewGuid():N}";
        var start = new ProcessStartInfo(fullPath)
        {
            WorkingDirectory = Path.GetDirectoryName(fullPath)!, UseShellExecute = false,
            CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
        };
        start.ArgumentList.Add("--data-dir"); start.ArgumentList.Add(Path.GetFullPath(options.DataDirectory));
        start.ArgumentList.Add("--pipe"); start.ArgumentList.Add(pipeName);
        var profile = ClientProfiles.Argument(options.Profile);
        start.ArgumentList.Add("--client-profile"); start.ArgumentList.Add(profile);
        if (options.AdoptUntaggedProfile)
        {
            start.ArgumentList.Add("--adopt-client-profile"); start.ArgumentList.Add(profile);
        }
        stopping = false;
        startupFailureReason = null;
        var startup = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        ready = startup;
        var child = new Process { StartInfo = start, EnableRaisingEvents = true };
        process = child;
        child.Exited += (_, _) =>
        {
            startup.TrySetException(new ControlException("early_exit", "服务退出，退出码：" + child.ExitCode));
            Log?.Invoke(stopping && child.ExitCode == 0 ? "info" : "error", "service_exit: " + child.ExitCode);
            Exited?.Invoke();
        };
        try { process.Start(); }
        catch { DisposeProcess(); throw; }
        try
        {
            stdoutTask = Task.Run(() => ReadLinesAsync(child.StandardOutput, "info"));
            stderrTask = Task.Run(() => ReadLinesAsync(child.StandardError, "error"));
            job = new OwnedJob(process);
            Control = new ControlClient(pipeName);
            // 标准输出的就绪公告只是第一步，还需通过管道核对同一 PID、实例、版本和协议。
            var announcement = await ready.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var status = await Control.SendAsync("status");
            var instanceId = announcement["instanceId"]?.GetValue<string>();
            if (announcement["pid"]?.GetValue<int>() != process.Id || status["pid"]?.GetValue<int>() != process.Id
                || string.IsNullOrEmpty(instanceId) || instanceId != status["instanceId"]?.GetValue<string>()
                || announcement["pipe"]?.GetValue<string>() != pipeName || announcement["protocolVersion"]?.GetValue<int>() != 1
                || announcement["clientProfile"]?.GetValue<string>() != profile || status["clientProfile"]?.GetValue<string>() != profile
                || status["protocolVersion"]?.GetValue<int>() != 1 || status["state"]?.GetValue<string>() != "running")
                throw new ControlException("readiness_mismatch", "服务就绪信息与实际管理实例不一致。");
            return status;
        }
        catch (Exception error)
        {
            if (IsAlive) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            if (stdoutTask is not null) await stdoutTask;
            if (stderrTask is not null) await stderrTask;
            var exitCode = process.ExitCode;
            var reason = startupFailureReason;
            DisposeProcess();
            if (error is ControlException { Code: "early_exit" } || reason is not null)
                throw new ControlException("early_exit", $"服务启动失败，退出码：{exitCode}；原因：{reason ?? "服务未报告结构化原因，请查看运行日志"}；服务端：{fullPath}");
            throw;
        }
    }

    private async Task ReadLinesAsync(StreamReader reader, string level)
    {
        // 分块读取并限制单行长度，避免服务端持续输出不换行文本耗尽管理器内存。
        var chars = new char[2048];
        var line = new StringBuilder();
        var oversized = false;
        try
        {
            int count;
            while ((count = await reader.ReadAsync(chars).ConfigureAwait(false)) != 0)
                for (var i = 0; i < count; i++)
                {
                    if (chars[i] == '\n')
                    {
                        EmitLine(line.ToString(), level, oversized);
                        line.Clear(); oversized = false;
                    }
                    else if (line.Length < ControlClient.MaximumFrame) line.Append(chars[i]);
                    else oversized = true;
                }
            if (line.Length > 0) EmitLine(line.ToString(), level, oversized);
        }
        catch (IOException error) { Log?.Invoke("error", "log_read_failed: " + error.Message); }
    }

    private void EmitLine(string line, string level, bool oversized)
    {
        if (oversized) { Log?.Invoke("error", "日志行超过 64 KiB，已截断：" + line); return; }
        Log?.Invoke(level, line.TrimEnd('\r'));
        try
        {
            if (JsonNode.Parse(line) is JsonObject obj)
            {
                if (obj["event"]?.GetValue<string>() == "ready") ready?.TrySetResult(obj);
                if (obj["event"]?.GetValue<string>() == "startup_or_runtime_failed"
                    && obj["reason"]?.GetValue<string>() is { Length: > 0 } reason)
                    Interlocked.Exchange(ref startupFailureReason, reason.Length > 256 ? reason[..256] : reason);
            }
        }
        catch (Exception error) when (error is System.Text.Json.JsonException or InvalidOperationException)
        { if (level != "error") Log?.Invoke("warning", "unstructured_stdout: " + error.GetType().Name); }
    }

    public async Task StopAsync()
    {
        if (process is null) return;
        stopping = true;
        if (IsAlive)
        {
            // 先请求服务端自行收尾；超时兜底仅针对本管理器创建并持有的实例。
            try { if (Control is not null) await Control.SendAsync("stop"); }
            catch (Exception error) when (error is IOException or TimeoutException or OperationCanceledException or ControlException)
            { Log?.Invoke("error", "stop_request_failed: " + error.Message); }
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8)); }
            catch (TimeoutException)
            {
                Log?.Invoke("error", "stop_timeout: 正在终止本管理器持有的服务进程。");
                if (IsAlive) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
        if (stdoutTask is not null) await stdoutTask;
        if (stderrTask is not null) await stderrTask;
        DisposeProcess();
    }

    private void DisposeProcess()
    {
        job?.Dispose(); job = null;
        process?.Dispose(); process = null;
        Control = null; stdoutTask = null; stderrTask = null;
    }
    public void Dispose() => DisposeProcess();
}
