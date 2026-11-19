namespace SnnuAutoLogin.Core;

/// <summary>
/// 重试策略：
/// - 密码错误：不重试（退避对凭证错误无意义），熔断等用户改配置；
/// - 门户不可达/整机无网：固定 30 秒静默重探（门户宕机用例）；
/// - 其余未知失败：指数退避 5s/10s/20s/60s（60s 封顶）。
/// </summary>
public static class RetryPolicy
{
    private static readonly int[] UnknownBackoffSeconds = { 5, 10, 20, 60 };

    /// <summary>返回下次重试延迟；null 表示不应重试（熔断）。</summary>
    public static TimeSpan? NextDelay(AuthOutcome failure, int attempt)
    {
        return failure switch
        {
            AuthOutcome.PasswordError => null,
            AuthOutcome.CaptchaNeeded => null,
            // RADIUS IP 冲突只能等旧会话老化或被强制下线：短间隔重试只会连续失败、
            // 并把门户的验证码惩罚一直"养"着，故固定 5 分钟一次。
            AuthOutcome.IpConflict => TimeSpan.FromMinutes(5),
            AuthOutcome.PortalUnreachable or AuthOutcome.NetworkOffline => TimeSpan.FromSeconds(30),
            _ => TimeSpan.FromSeconds(UnknownBackoffSeconds[Math.Clamp(attempt, 0, UnknownBackoffSeconds.Length - 1)]),
        };
    }
}
