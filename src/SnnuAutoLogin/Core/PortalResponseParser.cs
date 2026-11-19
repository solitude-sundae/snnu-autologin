using System.Text.RegularExpressions;

namespace SnnuAutoLogin.Core;

/// <summary>
/// 门户 HTML/文本响应解析器。纯函数集合，便于用真实采样样本做单元测试。
/// 所有解析都基于 docs/01 接口逆向文档的实测样本结构。
/// </summary>
public static partial class PortalResponseParser
{
    /// <summary>状态页隐藏域：&lt;input type="hidden" id="account" value="学号@运营商"/&gt;</summary>
    [GeneratedRegex(@"<input[^>]*id=""account""[^>]*value=""([^""]*)""", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex AccountInputRegex();

    [GeneratedRegex(@"<input[^>]*id=""ipaddr""[^>]*value=""([^""]*)""", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex IpInputRegex();

    [GeneratedRegex("""登录时间：\s*([0-9\-: ]+)""", RegexOptions.Compiled)]
    private static partial Regex LoginTimeRegex();

    /// <summary>门户错误提示单元格：&lt;td class="errormsg"&gt;中国联通认证失败：Rad:IP conflict !&lt;/td&gt;</summary>
    [GeneratedRegex(@"<(td|div|span)[^>]*class=""errormsg""[^>]*>(.*?)</\1>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled)]
    private static partial Regex ErrorBoxRegex();

    /// <summary>登录页提交前的验证码输入框（存在即表示本次登录必须先填验证码）。</summary>
    [GeneratedRegex(@"name\s*=\s*[""']checkcode[""']", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex CaptchaFieldRegex();

    private static readonly Regex Whitespace = new(@"\s+", RegexOptions.Compiled);

    /// <summary>判断页面是否为"已认证在线"状态页。</summary>
    public static bool LooksOnline(string html, KeywordSet keywords)
    {
        if (string.IsNullOrEmpty(html))
        {
            return false;
        }
        // 必须命中在线标记词之一（"当前登录账号" 或隐藏域），仅出现 account 字样不算
        return keywords.OnlineMarkers.Any(k => html.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// 判定登录 POST 响应属于哪一类结果。
    /// 优先级：门户错误框原文 → 各错误关键字 → 成功 → 未知。
    /// 说明（实测 2026-11-19）：登录失败时门户会把整张登录表单连同一段
    /// "中国联通认证失败：Rad:IP conflict !" 一起重画回来，验证码输入框也会随之出现；
    /// 若先按 checkcode 字段判定，真实错误（IP 冲突/密码错误）就被掩盖了。
    /// 因此这里以 errormsg 里的原文为准，checkcode 字段不参与本次判定。
    /// </summary>
    public static AuthOutcome ClassifyLoginResponse(string html, KeywordSet keywords)
    {
        if (string.IsNullOrEmpty(html))
        {
            return AuthOutcome.UnknownFailure;
        }

        // 一、门户明确给出的错误原文优先级最高
        var errorText = ExtractErrorText(html);
        if (!string.IsNullOrEmpty(errorText))
        {
            if (ContainsAny(errorText, keywords.IpConflict)) return AuthOutcome.IpConflict;
            if (ContainsAny(errorText, keywords.PasswordError)) return AuthOutcome.PasswordError;
            if (ContainsAny(errorText, keywords.AlreadyOnline)) return AuthOutcome.AlreadyOnline;
            if (ContainsAny(errorText, keywords.CaptchaNeeded)) return AuthOutcome.CaptchaNeeded;
            if (ContainsAny(errorText, keywords.LoginSuccess)) return AuthOutcome.Success;
            // 有错误原文但无法归类：继续走下面的通用判定（可能成功页也带 errormsg）
        }

        // 二、通用关键字（全文），IP 冲突仍排在最前
        if (ContainsAny(html, keywords.IpConflict)) return AuthOutcome.IpConflict;
        if (ContainsAny(html, keywords.PasswordError)) return AuthOutcome.PasswordError;
        if (ContainsAny(html, keywords.AlreadyOnline)) return AuthOutcome.AlreadyOnline;
        if (ContainsAny(html, keywords.CaptchaNeeded)) return AuthOutcome.CaptchaNeeded;
        if (ContainsAny(html, keywords.LoginSuccess)) return AuthOutcome.Success;
        if (LooksOnline(html, keywords)) return AuthOutcome.Success;
        return AuthOutcome.UnknownFailure;
    }

    /// <summary>
    /// 登录页（POST 之前 GET 到的表单页）是否已要求验证码。
    /// 与 <see cref="ClassifyLoginResponse"/> 区分：前者看"提交前表单有没有验证码框"，
    /// 后者看"提交后门户报了什么错"。
    /// </summary>
    public static bool RequiresCaptchaOnLoginPage(string? html)
        => !string.IsNullOrEmpty(html) && CaptchaFieldRegex().IsMatch(html);

    /// <summary>提取门户 errormsg 错误框的纯文本；没有错误框时返回空串。</summary>
    public static string ExtractErrorText(string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return string.Empty;
        }
        var m = ErrorBoxRegex().Match(html);
        if (!m.Success)
        {
            return string.Empty;
        }
        return ToPlainText(m.Groups[2].Value, 200);
    }

    /// <summary>从状态页提取会话信息（账号、IP、登录时间）。解析失败的字段为 null。</summary>
    public static PortalSessionInfo? ExtractSession(string html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return null;
        }
        var account = AccountInputRegex().Match(html).Groups[1].Value;
        if (string.IsNullOrWhiteSpace(account))
        {
            return null;
        }
        var ip = IpInputRegex().Match(html).Groups[1].Value;
        if (string.IsNullOrWhiteSpace(ip))
        {
            ip = null;
        }

        DateTime? loginTime = null;
        var timeText = LoginTimeRegex().Match(html).Groups[1].Value.Trim();
        if (DateTime.TryParse(timeText, out var parsed))
        {
            loginTime = parsed;
        }
        return new PortalSessionInfo(account, ip, loginTime);
    }

    /// <summary>
    /// 解析流量报表响应，形如 "总流量:6874.340,2635.943"（已用 MB, 剩余 MB）。
    /// </summary>
    public static FluxInfo? ParseFlux(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }
        var idx = body.IndexOf(':');
        if (idx < 0 || idx + 1 >= body.Length)
        {
            return null;
        }
        var parts = body[(idx + 1)..].Split(',');
        if (parts.Length < 2)
        {
            return null;
        }
        if (!decimal.TryParse(parts[0].Trim(), out var used) || !decimal.TryParse(parts[1].Trim(), out var free))
        {
            return null;
        }
        return new FluxInfo(used, free);
    }

    /// <summary>去除 HTML 标签与多余空白，用于气泡提示等纯文本场景。</summary>
    public static string ToPlainText(string html, int maxLength = 200)
    {
        if (string.IsNullOrEmpty(html))
        {
            return string.Empty;
        }
        var text = Whitespace.Replace(html, " ");
        var start = text.IndexOf('<');
        while (start >= 0)
        {
            var end = text.IndexOf('>', start + 1);
            if (end < 0)
            {
                break;
            }
            text = text.Remove(start, end - start + 1);
            start = text.IndexOf('<');
        }
        text = text.Trim();
        return text.Length <= maxLength ? text : text[..maxLength];
    }

    private static bool ContainsAny(string html, IEnumerable<string> keywords) =>
        keywords.Any(k => !string.IsNullOrWhiteSpace(k) && html.Contains(k, StringComparison.OrdinalIgnoreCase));
}
