using SnnuAutoLogin.Core;
using Xunit;

namespace SnnuAutoLogin.Tests;

/// <summary>账号/服务类型比对测试（v1.2.0 错配提醒的判定核心）。</summary>
public class AccountMatcherTests
{
    [Fact]
    public void 同学号同通道_匹配()
    {
        Assert.Equal(AccountVerdict.Match, AccountMatcher.Match("20231001@unicom", "20231001", "unicom"));
        Assert.Equal(AccountVerdict.Match, AccountMatcher.Match("20231001", "20231001", ""));
    }

    [Fact]
    public void 同学号不同通道_错配()
    {
        // 实测案例：在线为 @mobile，配置为 unicom
        Assert.Equal(AccountVerdict.SuffixMismatch, AccountMatcher.Match("20231001@mobile", "20231001", "unicom"));
        // 免费通道配置 vs 运营商在线
        Assert.Equal(AccountVerdict.SuffixMismatch, AccountMatcher.Match("20231001@unicom", "20231001", ""));
        // 运营商配置 vs 免费通道在线
        Assert.Equal(AccountVerdict.SuffixMismatch, AccountMatcher.Match("20231001", "20231001", "telecom"));
    }

    [Fact]
    public void 别人的账号_不提醒()
    {
        // 宿舍路由器上他人认证的会话
        Assert.Equal(AccountVerdict.OtherAccount, AccountMatcher.Match("20239999@unicom", "20231001", "unicom"));
        // 空值防御
        Assert.Equal(AccountVerdict.OtherAccount, AccountMatcher.Match("", "20231001", "unicom"));
        Assert.Equal(AccountVerdict.OtherAccount, AccountMatcher.Match("20231001@unicom", " ", "unicom"));
    }

    [Fact]
    public void 学号大小写不敏感_解析正确()
    {
        Assert.Equal(AccountVerdict.Match, AccountMatcher.Match("20231001@Unicom", "20231001", "unicom"));
        Assert.Equal("unicom", AccountMatcher.SuffixOf("20231001@unicom"));
        Assert.Equal("20231001", AccountMatcher.IdOf("20231001@unicom"));
        Assert.Equal("", AccountMatcher.SuffixOf("20231001"));
        Assert.Equal("20231001", AccountMatcher.IdOf("20231001"));
    }
}
