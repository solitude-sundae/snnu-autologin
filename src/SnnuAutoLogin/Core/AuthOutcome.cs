namespace SnnuAutoLogin.Core;

/// <summary>登录/探测结果分类。判定优先级必须与 <see cref="PortalResponseParser"/> 中的检查顺序一致。</summary>
public enum AuthOutcome
{
    /// <summary>登录成功（响应命中成功关键字，或已通过状态页二次验证）。</summary>
    Success,

    /// <summary>账号或密码错误——退避重试无意义，必须熔断并提示用户修改配置。</summary>
    PasswordError,

    /// <summary>该账号已在别处在线（同源 IP 重复登录顶替）。</summary>
    AlreadyOnline,

    /// <summary>
    /// RADIUS 侧 IP 冲突（实测报错 "Rad:IP conflict !"）：该 IP 已被别的会话占用，
    /// 或本账号在另一个 IP 上仍有未释放的会话。快速重试无用，只能等待会话老化或强制下线。
    /// </summary>
    IpConflict,

    /// <summary>门户要求验证码（checkcode 字段出现），自动登录被阻断，转人工。</summary>
    CaptchaNeeded,

    /// <summary>门户网络不可达（连接失败/超时）。</summary>
    PortalUnreachable,

    /// <summary>整机无网络（探测点与门户均不可达）。</summary>
    NetworkOffline,

    /// <summary>其余无法归类的情况，原文存入 captures 待人工分析。</summary>
    UnknownFailure,
}

/// <summary>状态页探测结果。</summary>
public enum PortalStatus
{
    /// <summary>已认证在线（页面含"当前登录账号"标记）。</summary>
    Online,

    /// <summary>未认证（被重定向到登录页或页面直接渲染登录表单）。</summary>
    Unauthenticated,

    /// <summary>门户不可达。</summary>
    Unreachable,
}

/// <summary>流量报表信息（单位 MB，来自 userstatus 报表接口）。</summary>
public sealed record FluxInfo(decimal UsedMb, decimal FreeMb);

/// <summary>状态页解析出的会话信息。</summary>
public sealed record PortalSessionInfo(string Account, string? Ip, DateTime? LoginTime);
