using System.Text.Json.Serialization;

namespace SnnuAutoLogin.Core;

/// <summary>
/// 响应关键字词典。初版来自 docs/01 接口逆向文档 §5 的推测词典，
/// 门户真实响应采样（captures 目录）确认后可直接在 config.json 中覆盖修订，无需改代码。
/// 匹配规则：不区分大小写，数组内任一命中即成立。
/// </summary>
public sealed class KeywordSet
{
    /// <summary>状态页"已在线"标记。</summary>
    public List<string> OnlineMarkers { get; set; } = new() { "当前登录账号", "id=\"account\" value" };

    /// <summary>登录成功。</summary>
    public List<string> LoginSuccess { get; set; } = new() { "登录成功", "loginsuccess", "success.jsp", "认证成功" };

    /// <summary>密码错误（熔断词，优先级最高）。</summary>
    public List<string> PasswordError { get; set; } = new() { "密码错误", "密码不正确", "用户名或密码错误", "账号或密码" };

    /// <summary>已在线/别处登录。</summary>
    public List<string> AlreadyOnline { get; set; } = new() { "已经在线", "已在线", "别处登录", "不要重复登录", "重复登录" };

    /// <summary>
    /// RADIUS 侧 IP 冲突（实测 2026-11-19 门户报错 "中国联通认证失败：Rad:IP conflict !"）。
    /// 快速重试会持续失败并触发门户验证码惩罚，必须长间隔等待。
    /// </summary>
    public List<string> IpConflict { get; set; } = new() { "Rad:IP conflict", "Rad: IP conflict", "IP conflict", "IP冲突", "IP 冲突" };

    /// <summary>需要验证码：仅在"验证码"确实是本次失败原因时命中（不包含 checkcode 字段本身）。</summary>
    public List<string> CaptchaNeeded { get; set; } = new() { "验证码错误", "验证码不正确", "输入验证码", "请输入验证码" };

    [JsonIgnore]
    public static KeywordSet Default => new();
}

/// <summary>门户端点配置（相对基址的路径），一般无需改动，预留 config.json 覆盖能力。</summary>
public sealed class PortalEndpoints
{
    public string BaseUrl { get; set; } = "http://202.117.144.205:8605/snnuportal/";
    public string LoginPage { get; set; } = "login.jsp";
    public string LoginAction { get; set; } = "login";
    public string StatusPage { get; set; } = "userstatus.jsp";
    public string FluxReport { get; set; } = "userstatus";
    public string Logoff { get; set; } = "logoff";
}
