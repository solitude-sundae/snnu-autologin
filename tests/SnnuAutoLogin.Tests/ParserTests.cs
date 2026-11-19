using SnnuAutoLogin.Core;
using Xunit;

namespace SnnuAutoLogin.Tests;

/// <summary>响应解析器测试。样本取自 docs/01 接口逆向文档的真实采集（账号已打码）。</summary>
public class ParserTests
{
    private readonly KeywordSet _kw = KeywordSet.Default;

    /// <summary>在线状态页真实样本（节选自 2026-09-23 采集）。</summary>
    private const string OnlineStatusHtml = """
        <html><head><meta http-equiv="Content-Type" content="text/html; charset=GB2312">
        <title>陕西师范大学网络Portal</title></head><body>
        <input type="hidden" id="sourceurl" value=""/>
        <input type="hidden" id="ipaddr" value="10.100.2.125"/>
        <input type="hidden" id="account" value="202****01@unicom"/>
        当前登录账号：<span class="zhengwen1">202****01@unicom</span>
        登录时间：2026-09-23 07:38:29
        当前IP：10.100.2.125
        <a href="logoff"><img src="image/duankai.gif" border="0"/></a>
        </body></html>
        """;

    [Fact]
    public void LooksOnline_真实在线页_判定在线()
    {
        Assert.True(PortalResponseParser.LooksOnline(OnlineStatusHtml, _kw));
    }

    [Theory]
    [InlineData("")]
    [InlineData("<html><body>登录页</body></html>")]
    [InlineData("<input type='text' name='account'/>请登录")]
    public void LooksOnline_非在线页_判定未在线(string html)
    {
        Assert.False(PortalResponseParser.LooksOnline(html, _kw));
    }

    [Fact]
    public void ClassifyLoginResponse_成功关键字()
    {
        Assert.Equal(AuthOutcome.Success, PortalResponseParser.ClassifyLoginResponse("<html>登录成功！</html>", _kw));
        Assert.Equal(AuthOutcome.Success, PortalResponseParser.ClassifyLoginResponse("LoginSuccess", _kw)); // 大小写不敏感
    }

    [Fact]
    public void ClassifyLoginResponse_登录回在线状态页_判成功()
    {
        // 实测（2026-09-23 捕获样本）：门户登录成功直接返回在线状态页，无"登录成功"字样
        Assert.Equal(AuthOutcome.Success, PortalResponseParser.ClassifyLoginResponse(OnlineStatusHtml, _kw));
    }

    [Fact]
    public void ClassifyLoginResponse_密码错误_优先于成功词()
    {
        // 防御性顺序：页面同时含"登录"与"密码错误"时必须判密码错误
        Assert.Equal(AuthOutcome.PasswordError,
            PortalResponseParser.ClassifyLoginResponse("<html>登录失败：密码错误！</html>", _kw));
    }

    [Fact]
    public void ClassifyLoginResponse_已在线与别处登录()
    {
        Assert.Equal(AuthOutcome.AlreadyOnline,
            PortalResponseParser.ClassifyLoginResponse("该用户已经在线", _kw));
        Assert.Equal(AuthOutcome.AlreadyOnline,
            PortalResponseParser.ClassifyLoginResponse("账号已在别处登录", _kw));
    }

    [Fact]
    public void ClassifyLoginResponse_验证码_只认明确文案而非字段存在()
    {
        // 回归（2026-11-19 线上故障）：登录失败时门户会把整张表单连验证码框一起重画，
        // 旧实现据此判成 CaptchaNeeded，掩盖了真正的 Rad:IP conflict 报错。
        Assert.Equal(AuthOutcome.UnknownFailure,
            PortalResponseParser.ClassifyLoginResponse("""<input name="checkcode" type="text"/>""", _kw));
        // 真正的验证码错误才有此文案
        Assert.Equal(AuthOutcome.CaptchaNeeded,
            PortalResponseParser.ClassifyLoginResponse("<div class=\"errormsg\">验证码错误，请重新输入</div>", _kw));
    }

    [Fact]
    public void ClassifyLoginResponse_Rad的IP冲突_优先于验证码字段()
    {
        // 真实捕获样本节选（2026-11-19，账号已脱敏）：错误框 + 重画的验证码表单
        const string realResponse = """
            <table><tr>
              <td class="errormsg" width="252">
                    中国联通认证失败：Rad:IP conflict !</td>
            </tr><tr>
              <td><input style="width:230px;" name="account" type="text"/></td>
              <td><input name="password" type="password"/></td>
              <td><input name="checkcode" type="text"/></td>
            </tr></table>
            """;
        Assert.Equal(AuthOutcome.IpConflict,
            PortalResponseParser.ClassifyLoginResponse(realResponse, _kw));
        Assert.Contains("Rad:IP conflict", PortalResponseParser.ExtractErrorText(realResponse));
    }

    [Fact]
    public void ClassifyLoginResponse_错误框里的密码错误_不受验证码字段干扰()
    {
        const string response = """
            <td class="errormsg">密码错误，请重新输入</td>
            <input name="checkcode" type="text"/>
            """;
        Assert.Equal(AuthOutcome.PasswordError,
            PortalResponseParser.ClassifyLoginResponse(response, _kw));
    }

    [Fact]
    public void RequiresCaptchaOnLoginPage_按表单字段判断()
    {
        // 提交前的干净登录页（2026-11-19 捕获，13377B，无验证码）
        Assert.False(PortalResponseParser.RequiresCaptchaOnLoginPage("""
            <form action="login" method="post">
              <input name="account" type="text"/>
              <input name="password" type="password"/>
            </form>
            """));
        // 门户开始要求验证码
        Assert.True(PortalResponseParser.RequiresCaptchaOnLoginPage("""
            <form action="login" method="post">
              <input name="account" type="text"/>
              <input name='checkcode' type="text"/>
            </form>
            """));
        Assert.False(PortalResponseParser.RequiresCaptchaOnLoginPage(null));
    }

    [Fact]
    public void ExtractErrorText_无错误框返回空()
    {
        Assert.Equal(string.Empty, PortalResponseParser.ExtractErrorText(OnlineStatusHtml));
        Assert.Equal(string.Empty, PortalResponseParser.ExtractErrorText(""));
    }

    [Fact]
    public void ClassifyLoginResponse_未知()
    {
        Assert.Equal(AuthOutcome.UnknownFailure,
            PortalResponseParser.ClassifyLoginResponse("<html>系统维护中</html>", _kw));
        Assert.Equal(AuthOutcome.UnknownFailure,
            PortalResponseParser.ClassifyLoginResponse("", _kw));
    }

    [Fact]
    public void ExtractSession_解析账号IP与时间()
    {
        var session = PortalResponseParser.ExtractSession(OnlineStatusHtml);
        Assert.NotNull(session);
        Assert.Equal("202****01@unicom", session.Account);
        Assert.Equal("10.100.2.125", session.Ip);
        Assert.NotNull(session.LoginTime);
        Assert.Equal(2026, session.LoginTime!.Value.Year);
    }

    [Fact]
    public void ExtractSession_无账号隐藏域_返回null()
    {
        Assert.Null(PortalResponseParser.ExtractSession("<html></html>"));
    }

    [Fact]
    public void ParseFlux_真实报表样本()
    {
        var flux = PortalResponseParser.ParseFlux("总流量:6874.340,2635.943");
        Assert.NotNull(flux);
        Assert.Equal(6874.340m, flux.UsedMb);
        Assert.Equal(2635.943m, flux.FreeMb);
    }

    [Theory]
    [InlineData("")]
    [InlineData("总流量")]
    [InlineData("总流量:abc,def")]
    [InlineData("总流量:123")]
    public void ParseFlux_非法输入_返回null(string body)
    {
        Assert.Null(PortalResponseParser.ParseFlux(body));
    }

    [Fact]
    public void ToPlainText_去标签去空白()
    {
        var text = PortalResponseParser.ToPlainText("<html><body>  登录 成功\n </body></html>");
        Assert.Equal("登录 成功", text);
    }
}
