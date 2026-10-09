namespace RichOnline.Resources;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        try
        {
            string root = args.Length > 0 ? Path.GetFullPath(args[0]) : AppContext.BaseDirectory;
            if (args.Length > 1 && args[1] == "--self-test") return SelfTests.Run(root, args.Length > 2 ? args[2] : Path.Combine(AppContext.BaseDirectory, "test-artifacts"));
            using var form = new MainForm(root);
            if (args.Length > 2 && args[1] == "--render") form.Shown += async (_, _) => { try { await form.RenderEvidence(args[2]); } finally { form.Close(); } };
            Application.Run(form); return 0;
        }
        catch (Exception error)
        {
            if (args.Contains("--self-test")) { Console.Error.WriteLine(error); return 1; }
            MessageBox.Show(error.Message, "资源工作台", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1;
        }
    }
}
