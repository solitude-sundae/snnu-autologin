using System.Net;
using System.Net.Http;
using System.Text;
using SnnuAutoLogin.Logging;

namespace SnnuAutoLogin.Core;

/// <summary>状态页探测结果（含原始响应，供捕获存档与解析）。</summary>
public sealed record StatusProbeResult(PortalStatus Status, string? Html, int? StatusCode, string? RedirectLocation);

/// <summary>登录请求参数。密码仅在内存中出现，绝不写日志/捕获文件。</summary>
public sealed record LoginRequest(string Account, string Password, string ServiceSuffix);

/// <summary>
/// 门户 HTTP 客户端：状态探测、模拟登录、流量查询。
/// 设计要点：
/// 1. 全部请求超时 5 秒（硬约束）；
/// 2. 禁用系统代理——门户按源 IP 识别会话，走代理会导致 IP 变化、认证错乱；
/// 3. 关闭自动重定向，手工解释 302（在线→状态页 / 未认证→登录页是核心判定信号）；
/// 4. 响应一律按字节读取后以 GB2312 解码（门户全站 GB2312）；
/// 5. 表单值按浏览器行为编码为 GB2312 字节再百分号转义。
/// </summary>
public sealed class PortalClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly PortalEndpoints _endpoints;
    private readonly KeywordSet _keywords;

    public PortalClient(PortalEndpoints endpoints, KeywordSet keywords, HttpMessageHandler? handler = null)
    {
        _endpoints = endpoints;
        _keywords = keywords;
        _http = handler == null
            ? new HttpClient(new HttpClientHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                CookieContainer = new CookieContainer(),
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            }, disposeHandler: true)
            : new HttpClient(handler, disposeHandler: false);
        _http.Timeout = TimeSpan.FromSeconds(5); // 硬约束：所有对外请求 ≤5s
    }

    /// <summary>探测状态页：判定当前源 IP 是否已认证。</summary>
    public async Task<StatusProbeResult> ProbeStatusAsync(CancellationToken ct = default)
    {
        var url = Url(_endpoints.StatusPage);
        try
        {
            using var resp = await _http.GetAsync(url, HttpCompletionOption.ResponseContentRead, ct);
            var html = await ReadBodyAsync(resp, ct);
            if ((int)resp.StatusCode is >= 300 and < 400)
            {
                // 实测：在线时状态页直接 200；出现 302 说明未认证（未认证时的跳转目标待实测，见 docs/01 §5）
                var location = resp.Headers.Location?.ToString() ?? string.Empty;
                return new StatusProbeResult(PortalStatus.Unauthenticated, html, (int)resp.StatusCode, location);
            }
            bool online = html != null && PortalResponseParser.LooksOnline(html, _keywords);
            return new StatusProbeResult(online ? PortalStatus.Online : PortalStatus.Unauthenticated,
                html, (int)resp.StatusCode, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TimeoutException or OperationCanceledException)
        {
            Log.Debug($"状态页探测失败: {ex.GetType().Name} {ex.Message}");
            return new StatusProbeResult(PortalStatus.Unreachable, null, null, null);
        }
    }

    /// <summary>获取登录页 HTML（用于验证码检测与离线样本捕获）。</summary>
    public async Task<(bool Reachable, string? Html)> GetLoginPageAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync(Url(_endpoints.LoginPage), ct);
            var html = await ReadBodyAsync(resp, ct);
            return (true, html);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TimeoutException or OperationCanceledException)
        {
            Log.Debug($"登录页获取失败: {ex.GetType().Name} {ex.Message}");
            return (false, null);
        }
    }

    /// <summary>
    /// 模拟登录：POST account/password/yys（yys 为空即校园网免费通道，不发送该字段）。
    /// 返回结果类别与响应原文（原文用于捕获存档，不含密码）。
    /// </summary>
    public async Task<(AuthOutcome Outcome, string? ResponseHtml)> LoginAsync(LoginRequest req, CancellationToken ct = default)
    {
        var form = new StringBuilder();
        AppendForm(form, "account", req.Account);
        AppendForm(form, "password", req.Password);
        if (!string.IsNullOrEmpty(req.ServiceSuffix))
        {
            AppendForm(form, "yys", req.ServiceSuffix);
        }

        string? body = null;
        try
        {
            using var content = new StringContent(form.ToString(), Encoding.ASCII, "application/x-www-form-urlencoded");
            using var resp = await _http.PostAsync(Url(_endpoints.LoginAction), content, ct);
            body = await ReadBodyAsync(resp, ct);

            // 响应体可直接分类时以响应体为准（错误页通常是 200 + 错误文案）
            if (!string.IsNullOrWhiteSpace(body))
            {
                var outcome = PortalResponseParser.ClassifyLoginResponse(body, _keywords);
                if (outcome != AuthOutcome.UnknownFailure)
                {
                    return (outcome, body);
                }
            }

            // 空体/未知体 + 302 → 以跳转目标与状态页二次验证判定
            if ((int)resp.StatusCode is >= 300 and < 400)
            {
                var location = resp.Headers.Location?.ToString() ?? string.Empty;
                if (location.Contains("userstatus", StringComparison.OrdinalIgnoreCase) ||
                    location.Contains("success", StringComparison.OrdinalIgnoreCase))
                {
                    var verify = await ProbeStatusAsync(ct);
                    if (verify.Status == PortalStatus.Online)
                    {
                        return (AuthOutcome.Success, body);
                    }
                }
                else if (location.Contains("login", StringComparison.OrdinalIgnoreCase))
                {
                    // 被弹回登录页：拉取登录页文案再分类（密码错误/验证码可能重渲染在页面上）
                    var (_, loginHtml) = await GetLoginPageAsync(ct);
                    if (!string.IsNullOrWhiteSpace(loginHtml))
                    {
                        var reclassified = PortalResponseParser.ClassifyLoginResponse(loginHtml, _keywords);
                        return (reclassified, loginHtml);
                    }
                }
            }
            return (AuthOutcome.UnknownFailure, body);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TimeoutException or OperationCanceledException)
        {
            Log.Debug($"登录请求失败: {ex.GetType().Name} {ex.Message}");
            return (AuthOutcome.PortalUnreachable, body);
        }
    }

    /// <summary>查询流量报表：GET userstatus?ipaddr=…&amp;account=学号@运营商。</summary>
    public async Task<FluxInfo?> GetFluxAsync(string ipaddr, string account, CancellationToken ct = default)
    {
        try
        {
            var url = $"{Url(_endpoints.FluxReport)}?ipaddr={Uri.EscapeDataString(ipaddr)}&account={Uri.EscapeDataString(account)}";
            var body = await _http.GetStringAsync(url, ct);
            return PortalResponseParser.ParseFlux(body);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TimeoutException or OperationCanceledException)
        {
            return null;
        }
    }

    /// <summary>
    /// 下线当前会话（GET logoff）。仅用于假在线自愈：清掉"说谎"的旧会话后重登，
    /// 迷新建代拨出口隧道。返回门户是否可达（响应内容无关紧要）。
    /// </summary>
    public async Task<bool> LogoffAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync(Url(_endpoints.Logoff), ct);
            return true;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or TimeoutException or OperationCanceledException)
        {
            Log.Debug($"下线请求失败: {ex.GetType().Name} {ex.Message}");
            return false;
        }
    }

    /// <summary>门户状态页完整 URL（供"打开门户"菜单使用）。</summary>
    public string StatusPageUrl => Url(_endpoints.StatusPage);

    private string Url(string relative) => _endpoints.BaseUrl.TrimEnd('/') + "/" + relative.TrimStart('/');

    /// <summary>按浏览器行为编码表单值：GB2312 字节 → 百分号转义。</summary>
    private static void AppendForm(StringBuilder sb, string name, string value)
    {
        if (sb.Length > 0)
        {
            sb.Append('&');
        }
        sb.Append(name).Append('=');
        var bytes = Encoding.GetEncoding("GB2312").GetBytes(value);
        foreach (var b in bytes)
        {
            if (char.IsAsciiLetterOrDigit((char)b) || b is (byte)'-' or (byte)'_' or (byte)'.' or (byte)'~')
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('%').Append(b.ToString("X2"));
            }
        }
    }

    /// <summary>严格 UTF-8 解码器：遇到非法字节序列抛异常，用于判断响应到底是不是 UTF-8。</summary>
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static readonly Encoding Gb2312 = Encoding.GetEncoding("GB2312");

    /// <summary>
    /// 门户绝大多数页面是 GB2312，但实测（2026-11-19）登录失败页虽声明 charset=GB2312，
    /// 字节实际是 UTF-8：按 GB2312 解会把"中国联通认证失败"解成乱码。
    /// 故先用严格 UTF-8 试解（GB2312 的中文几乎不可能构成合法 UTF-8 序列），失败才回落 GB2312。
    /// </summary>
    private static async Task<string?> ReadBodyAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        return bytes.Length == 0 ? null : DecodeBody(bytes);
    }

    /// <summary>编码判定（同步，避免在异步方法中使用 Span）。</summary>
    private static string DecodeBody(byte[] bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        }
        try
        {
            return StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return Gb2312.GetString(bytes);
        }
    }

    public void Dispose() => _http.Dispose();
}
