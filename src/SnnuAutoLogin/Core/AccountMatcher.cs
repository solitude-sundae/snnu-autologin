namespace SnnuAutoLogin.Core;

/// <summary>在线账号与本地配置的比对结论。</summary>
public enum AccountVerdict
{
    /// <summary>同一学号且运营商通道一致。</summary>
    Match,

    /// <summary>同一学号，但在线通道与配置的服务类型不一致（配置错配，应提醒）。</summary>
    SuffixMismatch,

    /// <summary>在线的是别人的账号（如宿舍路由器上他人认证），不提醒。</summary>
    OtherAccount,
}

/// <summary>
/// 账号比对纯函数。状态页在线账号形如 "学号" 或 "学号@unicom"，
/// 与本地配置（学号 + 服务后缀）比对，用于"服务类型配错"自动提醒。
/// </summary>
public static class AccountMatcher
{
    public static string SuffixOf(string account)
    {
        var i = account.IndexOf('@');
        return i < 0 ? string.Empty : account[(i + 1)..];
    }

    public static string IdOf(string account)
    {
        var i = account.IndexOf('@');
        return i < 0 ? account : account[..i];
    }

    public static AccountVerdict Match(string onlineAccount, string configStudentId, string configSuffix)
    {
        if (string.IsNullOrWhiteSpace(onlineAccount) || string.IsNullOrWhiteSpace(configStudentId))
        {
            return AccountVerdict.OtherAccount;
        }
        if (!string.Equals(IdOf(onlineAccount), configStudentId.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return AccountVerdict.OtherAccount;
        }
        return string.Equals(SuffixOf(onlineAccount), configSuffix, StringComparison.OrdinalIgnoreCase)
            ? AccountVerdict.Match
            : AccountVerdict.SuffixMismatch;
    }
}
