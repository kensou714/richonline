using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RichOnline.Admin;

internal sealed record ClientStopTarget(string Executable, string ServerExecutable, int? ServerPid);
internal sealed record ClientStopResult(int Matched, int Closed, int Forced, int Failed, int Unverified);

internal static class ClientStop
{
    public static Task<ClientStopResult> StopAsync(ClientStopTarget target, Action<string, string> log) =>
        Task.Run(async () =>
        {
            var expected = Path.GetFullPath(target.Executable);
            if (!Path.IsPathFullyQualified(target.Executable) || !File.Exists(expected)
                || !Path.GetFileName(expected).Equals("RnClient.exe", StringComparison.OrdinalIgnoreCase))
                throw new ControlException("client_path_unconfirmed", "请选择存在的客户端 RnClient.exe 完整路径，再结束进程。");
            if (expected.Equals(Path.GetFullPath(target.ServerExecutable), StringComparison.OrdinalIgnoreCase))
                throw new ControlException("client_is_server", "客户端路径与服务端相同，已拒绝结束。");
            var matched = 0; var closed = 0; var forced = 0; var failed = 0; var unverified = 0;
            // 同名仅用于缩小候选；核实完整镜像路径后才允许关闭，避免影响另一套客户端。
            foreach (var process in Process.GetProcessesByName("RnClient"))
            {
                using (process)
                {
                    var verified = false;
                    try
                    {
                        if (process.Id == Environment.ProcessId || process.Id == target.ServerPid) continue;
                        var handle = process.SafeHandle;
                        var actual = new StringBuilder(32768); var size = actual.Capacity;
                        if (!QueryFullProcessImageName(handle, 0, actual, ref size))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        if (!Path.GetFullPath(actual.ToString()).Equals(expected, StringComparison.OrdinalIgnoreCase)) continue;
                        verified = true;
                        matched++;
                        if (process.HasExited) { closed++; log("info", $"client_already_exited: pid={process.Id}"); continue; }
                        var requested = process.CloseMainWindow();
                        log("info", $"client_close_requested: pid={process.Id}, window_message={requested}");
                        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); }
                        catch (TimeoutException)
                        {
                            if (!process.HasExited)
                            {
                                // 正常关闭超时只终止已核实的单个进程，不扩大到其进程树。
                                process.Kill(entireProcessTree: false);
                                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
                                forced++; log("warning", $"client_force_terminated: pid={process.Id}");
                                continue;
                            }
                        }
                        closed++; log("info", $"client_closed: pid={process.Id}");
                    }
                    catch (Exception error) when (error is Win32Exception or InvalidOperationException or TimeoutException)
                    {
                        if (!verified) unverified++;
                        failed++;
                        log("error", $"client_stop_failed: pid={process.Id}, code={error.GetType().Name}, reason={error.Message}");
                    }
                }
            }
            if (matched == 0) log(unverified > 0 ? "warning" : "info", unverified > 0
                ? "client_path_unconfirmed: 存在无法核实路径的进程，已跳过。" : "client_not_running: 配置路径的客户端未运行。");
            return new ClientStopResult(matched, closed, forced, failed, unverified);
        });

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder path, ref int size);
}
