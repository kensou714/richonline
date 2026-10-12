using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.FileProviders;
using RichOnline.Website;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("website.json", optional: false, reloadOnChange: false);
var origin = new Uri(builder.Configuration["PublicOrigin"] ?? throw new InvalidOperationException("PublicOrigin required"));
if (origin.Scheme != "https" || origin.AbsolutePath != "/" || !string.IsNullOrEmpty(origin.Query))
    throw new InvalidOperationException("PublicOrigin must be an HTTPS origin");
var stateRoot = Path.GetFullPath(builder.Configuration["StateDirectory"] ?? throw new InvalidOperationException("StateDirectory required"));
Directory.CreateDirectory(stateRoot);
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
builder.Logging.AddEventLog(o => o.SourceName = "RichOnline.Website");
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    k.Limits.MaxRequestBodySize = 4096;
    k.Limits.MaxRequestHeaderCount = 40;
    k.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
    using var pem = X509Certificate2.CreateFromPemFile(
        builder.Configuration["CertificateFile"]!, builder.Configuration["PrivateKeyFile"]!);
    var certificate = new X509Certificate2(pem.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.MachineKeySet);
    var chain = new X509Certificate2Collection();
    chain.ImportFromPemFile(builder.Configuration["CertificateFile"]!);
    k.Listen(IPAddress.Parse(builder.Configuration["BindAddress"] ?? "127.0.0.1"), origin.Port,
        endpoint => endpoint.UseHttps(https =>
        {
            https.ServerCertificate = certificate;
            https.ServerCertificateChain = chain;
        }));
});
builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(stateRoot, "keys")))
    .ProtectKeysWithDpapi(protectToLocalMachine: true).SetApplicationName("RichOnline.Website");
builder.Services.AddAntiforgery(o =>
{
    o.HeaderName = "X-CSRF-Token";
    o.Cookie.Name = "__Host-RichOnline-CSRF";
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.HttpOnly = true;
});
builder.Services.AddSingleton(new NativeAccounts(builder.Configuration["PipeName"] ?? "richonline-production"));
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ =>
        RateLimitPartition.GetFixedWindowLimiter("global", _ => new FixedWindowRateLimiterOptions
        { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.AddPolicy("account", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ => new FixedWindowRateLimiterOptions
        { PermitLimit = 12, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "60";
        await context.HttpContext.Response.WriteAsJsonAsync(new { error = "操作较频繁，请一分钟后再试。" }, token);
    };
});
var app = builder.Build();
app.Use(async (ctx, next) =>
{
    if (!string.Equals(ctx.Request.Host.Value, origin.Authority, StringComparison.OrdinalIgnoreCase))
    { ctx.Response.StatusCode = 400; return; }
    ctx.Response.Headers.XContentTypeOptions = "nosniff";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
    ctx.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    if (ctx.Request.Path.StartsWithSegments("/api")) ctx.Response.Headers.CacheControl = "no-store";
    await next();
});
// 图鉴作为同站子目录独立加载，大型 JSON 和音频不进入首页。
var catalog = Path.Combine(app.Environment.ContentRootPath, "catalog");
app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(catalog), RequestPath = "/catalog" });
app.UseStaticFiles();
app.UseRateLimiter();
app.MapGet("/health", () => Results.Json(new { website = "ready", version = builder.Configuration["SourceCommit"] }));
app.MapGet("/api/token", (HttpContext ctx, IAntiforgery csrf) => Results.Json(new { token = csrf.GetAndStoreTokens(ctx).RequestToken }));
app.MapPost("/api/{action}", async (string action, HttpContext ctx, IAntiforgery csrf, NativeAccounts accounts) =>
{
    try
    {
        if (!ctx.Request.IsHttps || ctx.Request.Headers.Origin != origin.GetLeftPart(UriPartial.Authority))
            return Results.Json(new { error = "请从官网页面提交。" }, statusCode: 403);
        await csrf.ValidateRequestAsync(ctx);
        if (!ctx.Request.HasJsonContentType()) return Results.StatusCode(415);
        var body = await ctx.Request.ReadFromJsonAsync<JsonObject>(ctx.RequestAborted);
        if (body is null || action is not ("register" or "account" or "password" or "claim"))
            return Results.BadRequest(new { error = "请求格式不正确。" });
        var result = await accounts.Send(action, body, ctx.RequestAborted);
        return Results.Json(result);
    }
    catch (AntiforgeryValidationException) { return Results.Json(new { error = "页面已失效，请刷新后重试。" }, statusCode: 403); }
    catch (AccountError e)
    {
        var message = e.Message switch
        {
            "website_credentials_invalid" => "账号或密码不正确。",
            "account_exists" => "该账号已被注册，请换一个账号。",
            "website_registration_closed" => "当前暂未开放注册。",
            "website_username_format" => "账号须为 4～20 位英文字母、数字或下划线。",
            "website_password_format" => "密码须为 8～32 位英文字母、数字或页面提示的符号。",
            "website_balance_limit" => "当前代币余额不少于 10,000，暂不能领取。",
            "website_role_invalid" or "website_role_missing" => "请先查询并选择本账号的角色。",
            "website_operation_invalid" => "申请编号无效，请重新查询余额后申请。",
            "request_unknown_field" or "request_value_invalid" or "control_payload_invalid" => "请求格式不正确。",
            _ => "账号服务暂不可用，请稍后重试；领取操作重试会沿用同一申请编号。"
        };
        return Results.Json(new { error = message }, statusCode: 400);
    }
    catch (System.Text.Json.JsonException) { return Results.BadRequest(new { error = "请求格式不正确。" }); }
    catch (Exception e) when (e is IOException or OperationCanceledException)
    { return Results.Json(new { error = "服务响应中断，请稍后重试。若正在领取，请勿另开页面重复申请。" }, statusCode: 503); }
}).RequireRateLimiting("account");
foreach (var path in new[] { "/", "/register", "/password", "/claim" })
    app.MapGet(path, () => Results.File(Path.Combine(app.Environment.WebRootPath, "index.html"), "text/html; charset=utf-8"));
app.MapGet("/catalog", (HttpContext ctx) => ctx.Request.Path.Value!.EndsWith('/')
    ? Results.File(Path.Combine(catalog, "index.html"), "text/html; charset=utf-8")
    : Results.Redirect("/catalog/"));
app.MapGet("/MEMBER/LoginForms.asp", () => Results.Redirect("/register"));
app.MapGet("/MEMBER/ChangePassword.asp", () => Results.Redirect("/password"));
app.MapGet("/gameinfo/index-gameinfo-10.aspx", () => Results.Redirect("/claim"));
app.Run();
