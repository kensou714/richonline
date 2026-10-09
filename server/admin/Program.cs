namespace RichOnline.Admin;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Length >= 2 && args[0] == "--gui-self-test")
            return MainForm.RunGuiSmokeTest(args[1], args.Skip(2).ToArray());
        if (args.Length == 3 && args[0] == "--startup-self-test")
            return StartupTests.RunAsync(args[1], args[2]).GetAwaiter().GetResult();
        if (args.Length == 3 && args[0] == "--client-stop-test-window")
        { ClientStopTests.RunWindow(args.Skip(1).ToArray()); return 0; }
        if (args.Length == 2 && args[0] == "--client-stop-self-test")
            return ClientStopTests.RunAsync(args[1]).GetAwaiter().GetResult();
        if (args.Length > 0 && args[0] == "--self-test")
            return ControlTests.RunAsync(args.Skip(1).ToArray()).GetAwaiter().GetResult();
        if (args.Length == 2 && args[0] == "--log-self-test")
            return MainForm.RunLogFloodTest(args[1]);
        try { Application.Run(new MainForm(args)); }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "管理器启动失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        return 0;
    }
}
