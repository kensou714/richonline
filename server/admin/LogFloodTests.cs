using System.Diagnostics;
using System.Text.Json.Nodes;

namespace RichOnline.Admin;

internal sealed partial class MainForm
{
    internal static int RunLogFloodTest(string output)
    {
        var report = new JsonObject { ["surface"] = "WinForms queue/consumer logic; no OS interaction or screenshot" };
        try
        {
            using var form = new MainForm([]);
            form.logTimer.Stop();
            for (var index = 0; index < 10000; index++) form.QueueLog("info", "flood " + index);
            RequireLogTest(form.pendingLogs.Count == MaximumLogs, "Pending queue cap");
            RequireLogTest(form.DrainPendingLogs() == MaximumLogsPerTick, "One tick consumes exactly its budget from backlog");
            RequireLogTest(form.pendingLogs.Count == 1500, "Backlog remains for later ticks");
            var maxConsumed = 0;
            var rounds = 0;
            var timer = Stopwatch.StartNew();
            var producer = Task.Run(() => Parallel.For(0, 50000, index => form.QueueLog("info", "parallel flood " + index)));
            while (!producer.IsCompleted || !form.pendingLogs.IsEmpty)
            {
                var consumed = form.DrainPendingLogs();
                maxConsumed = Math.Max(maxConsumed, consumed);
                RequireLogTest(consumed <= MaximumLogsPerTick && form.logs.Count <= MaximumLogs, "Per-tick and visible bounds");
                rounds++;
                if (timer.Elapsed > TimeSpan.FromSeconds(20)) throw new TimeoutException("Log producer/consumer did not finish within 20 seconds");
                Thread.Yield();
            }
            producer.GetAwaiter().GetResult();
            form.QueueLog("error", "final diagnostic");
            form.DrainPendingLogs();
            RequireLogTest(form.logs.Last().Detail == "final diagnostic", "Latest error survives flood");
            form.RenderLogs();
            RequireLogTest(form.logView.Items.Count == MaximumLogs, "Rendered row cap");
            report["ok"] = true;
            report["produced"] = 60001;
            report["pendingCapacity"] = MaximumLogs;
            report["maximumConsumedInOneTick"] = maxConsumed;
            report["tickCount"] = rounds;
            report["visibleRows"] = form.logView.Items.Count;
            report["elapsedMilliseconds"] = timer.ElapsedMilliseconds;
            form.logTimer.Dispose();
        }
        catch (Exception error)
        {
            report["ok"] = false; report["error"] = error.GetType().Name; report["message"] = error.Message;
        }
        File.WriteAllText(Path.GetFullPath(output), report.ToJsonString(JsonFormatting.Indented));
        return report["ok"]?.GetValue<bool>() == true ? 0 : 1;
    }
    private static void RequireLogTest(bool condition, string behavior)
    {
        if (!condition) throw new InvalidOperationException(behavior);
    }
}
