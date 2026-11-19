using System.Net;
using System.Text;
using SnnuAutoLogin.Core;
using Xunit;

namespace SnnuAutoLogin.Tests;

/// <summary>
/// 门户客户端 HTTP 行为测试：用假 HttpMessageHandler 模拟门户响应，
/// 覆盖 GB2312 解码、表单编码、302 判定、登录结果分类。
/// </summary>
public class PortalClientTests : IDisposable
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = new();

        /// <summary>请求体在响应阶段即读出缓存（客户端会 using 释放 content，事后不可再读）。</summary>
        public List<string?> Bodies { get; } = new();

        public Func<HttpRequestMessage, int, HttpResponseMessage> Respond { get; set; } =
            (_, _) => new HttpResponseMessage(HttpStatusCode.NotFound);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Bodies.Add(request.Content == null
                ? null
                : request.Content.ReadAsStringAsync(ct).GetAwaiter().GetResult());
            Requests.Add(request);
            return Task.FromResult(Respond(request, Requests.Count));
        }
    }

    private static HttpResponseMessage Gb2312Page(string html, HttpStatusCode code = HttpStatusCode.OK)
    {
        return new HttpResponseMessage(code)
        {
            Content = new ByteArrayContent(Gb.Bytes(html)),
        };
    }

    private static HttpResponseMessage Redirect(string location) => new(HttpStatusCode.Redirect)
    {
        Headers = { Location = new Uri(location, UriKind.RelativeOrAbsolute) },
    };

    private static readonly string OnlinePage =
        """
        <html><body>
        <input type="hidden" id="ipaddr" value="10.100.2.125"/>
        <input type="hidden" id="account" value="20231001@unicom"/>
        当前登录账号：<span>20231001@unicom</span>
        </body></html>
        """;

    private readonly FakeHandler _handler = new();

    private PortalClient CreateClient() =>
        new(new PortalEndpoints(), KeywordSet.Default, _handler);

    public void Dispose() => _handler.Dispose();

    [Fact]
    public async Task 状态页在线_Gb2312解码并提取会话()
    {
        _handler.Respond = (req, _) => req.Method == HttpMethod.Get
            ? Gb2312Page(OnlinePage)
            : new HttpResponseMessage(HttpStatusCode.NotFound);

        using var client = CreateClient();
        var probe = await client.ProbeStatusAsync();
        Assert.Equal(PortalStatus.Online, probe.Status);
        var session = PortalResponseParser.ExtractSession(probe.Html!);
        Assert.Equal("20231001@unicom", session!.Account);
    }

    [Fact]
    public async Task 状态页302到登录页_判定未认证()
    {
        _handler.Respond = (req, n) => n == 1
            ? Redirect("http://202.117.144.205:8605/snnuportal/login.jsp")
            : Gb2312Page(OnlinePage);

        using var client = CreateClient();
        var probe = await client.ProbeStatusAsync();
        Assert.Equal(PortalStatus.Unauthenticated, probe.Status);
        Assert.NotNull(probe.RedirectLocation);
    }

    [Fact]
    public async Task 状态页连接异常_判定不可达()
    {
        _handler.Respond = (_, _) => throw new HttpRequestException("连接超时");
        using var client = CreateClient();
        var probe = await client.ProbeStatusAsync();
        Assert.Equal(PortalStatus.Unreachable, probe.Status);
    }

    [Fact]
    public async Task 登录成功_响应含成功关键字()
    {
        _handler.Respond = (req, _) =>
        {
            if (req.Method == HttpMethod.Post)
            {
                return Gb2312Page("<html><body>登录成功！欢迎使用陕西师范大学校园网</body></html>");
            }
            return Gb2312Page(OnlinePage);
        };

        using var client = CreateClient();
        var (outcome, html) = await client.LoginAsync(new LoginRequest("20231001", "pw123", "unicom"));
        Assert.Equal(AuthOutcome.Success, outcome);
        Assert.Contains("登录成功", html);

        // 请求体：字段齐全，GB2312 百分号编码（此处全 ASCII 与 UTF-8 一致）
        Assert.Equal("account=20231001&password=pw123&yys=unicom", _handler.Bodies[0]);
        Assert.Equal("application/x-www-form-urlencoded",
            _handler.Requests[0].Content!.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task 登录成功_响应为在线状态页_判成功()
    {
        // 实测（2026-09-23 捕获）：门户登录成功直接返回在线状态页（无"登录成功"字样）
        _handler.Respond = (req, _) => req.Method == HttpMethod.Post
            ? Gb2312Page(OnlinePage)
            : Gb2312Page(OnlinePage);

        using var client = CreateClient();
        var (outcome, html) = await client.LoginAsync(new LoginRequest("20231001", "pw123", "unicom"));
        Assert.Equal(AuthOutcome.Success, outcome);
        Assert.Contains("当前登录账号", html);
    }

    [Fact]
    public async Task 登录_校园网免费通道_不提交yys字段()
    {
        _handler.Respond = (req, _) =>
        {
            if (req.Method == HttpMethod.Post)
            {
                return Gb2312Page("登录成功");
            }
            return Gb2312Page(OnlinePage);
        };

        using var client = CreateClient();
        var (outcome, _) = await client.LoginAsync(new LoginRequest("20231001", "pw123", ""));
        Assert.Equal(AuthOutcome.Success, outcome);
        Assert.Equal("account=20231001&password=pw123", _handler.Bodies[0]);
    }

    [Fact]
    public async Task 登录_密码错误分类()
    {
        _handler.Respond = (req, _) => req.Method == HttpMethod.Post
            ? Gb2312Page("<html><body>密码错误，请重新输入！</body></html>")
            : Gb2312Page(OnlinePage);

        using var client = CreateClient();
        var (outcome, _) = await client.LoginAsync(new LoginRequest("20231001", "bad", "unicom"));
        Assert.Equal(AuthOutcome.PasswordError, outcome);
    }

    [Fact]
    public async Task 登录302到状态页_二次复核判成功()
    {
        // POST login → 302 userstatus.jsp；随后 ProbeStatus 复核返回在线页
        _handler.Respond = (req, n) =>
        {
            if (req.Method == HttpMethod.Post && n == 1)
            {
                return Redirect("/snnuportal/userstatus.jsp");
            }
            if (req.Method == HttpMethod.Get && n == 2)
            {
                return Gb2312Page(OnlinePage);
            }
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        };

        using var client = CreateClient();
        var (outcome, _) = await client.LoginAsync(new LoginRequest("20231001", "pw", "unicom"));
        Assert.Equal(AuthOutcome.Success, outcome);
    }

    [Fact]
    public async Task 表单值含中文_按Gb2312百分号编码()
    {
        _handler.Respond = (req, _) =>
        {
            if (req.Method == HttpMethod.Post)
            {
                return Gb2312Page("登录成功");
            }
            return Gb2312Page(OnlinePage);
        };

        using var client = CreateClient();
        await client.LoginAsync(new LoginRequest("20231001", "中文pw", "unicom"));
        // "中文" 的 GB2312 字节为 D6 D0 CE C4
        Assert.Contains("password=%D6%D0%CE%C4pw", _handler.Bodies[0]);
    }

    [Fact]
    public async Task 响应声明GB2312但实为UTF8字节_仍正确解码()
    {
        // 实测缺陷（2026-11-19）：失败页声明 GB2312，字节却是 UTF-8，
        // 按 GB2312 解会把"中国联通认证失败"解成乱码，弹给用户的报错也变乱码。
        const string html = "<html><body><td class=\"errormsg\">中国联通认证失败：Rad:IP conflict !</td></body></html>";
        _handler.Respond = (_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(html)),
        };

        using var client = CreateClient();
        var (outcome, body) = await client.LoginAsync(new LoginRequest("20231001", "pw", "unicom"));
        Assert.Equal(AuthOutcome.IpConflict, outcome);
        Assert.Contains("中国联通认证失败", body);
    }

    [Fact]
    public async Task 真实捕获的失败页_判为IP冲突而非验证码()
    {
        // 夹具为 2026-11-19 线上真实响应（已脱敏 IP）：errormsg 报 Rad:IP conflict，
        // 页面同时带被注释掉的 checkcode 字段——旧实现据此误判成 CaptchaNeeded。
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "login_resp_ipconflict.html");
        Assert.True(File.Exists(path), $"缺少测试夹具: {path}");
        var html = await File.ReadAllTextAsync(path);

        Assert.Equal(AuthOutcome.IpConflict, PortalResponseParser.ClassifyLoginResponse(html, KeywordSet.Default));
        Assert.Contains("Rad:IP conflict", PortalResponseParser.ExtractErrorText(html));
    }

    [Fact]
    public async Task 流量查询_解析已用剩余()
    {
        _handler.Respond = (_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("总流量:100.5,2047.5"),
        };

        using var client = CreateClient();
        var flux = await client.GetFluxAsync("10.100.2.125", "20231001@unicom");
        Assert.NotNull(flux);
        Assert.Equal(100.5m, flux!.UsedMb);
        Assert.Equal(2047.5m, flux.FreeMb);
        var last = _handler.Requests.Last();
        Assert.Contains("ipaddr=10.100.2.125", last.RequestUri!.Query);
        Assert.Contains("account=20231001%40unicom", last.RequestUri.Query);
    }

    [Fact]
    public async Task 下线_请求logoff端点_可达返回true()
    {
        _handler.Respond = (_, _) => new HttpResponseMessage(HttpStatusCode.OK);
        using var client = CreateClient();
        Assert.True(await client.LogoffAsync());
        Assert.EndsWith("/snnuportal/logoff", _handler.Requests[0].RequestUri!.ToString());
    }

    [Fact]
    public async Task 下线_门户不可达返回false()
    {
        _handler.Respond = (_, _) => throw new HttpRequestException("连接超时");
        using var client = CreateClient();
        Assert.False(await client.LogoffAsync());
    }
}
