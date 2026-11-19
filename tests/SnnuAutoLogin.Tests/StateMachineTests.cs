using SnnuAutoLogin.Core;
using Xunit;

namespace SnnuAutoLogin.Tests;

public class StateMachineTests
{
    [Fact]
    public void 初始状态为离线()
    {
        var sm = new LoginStateMachine();
        Assert.Equal(AppState.Offline, sm.Current);
    }

    [Fact]
    public void 合法迁移触发事件并更新状态()
    {
        var sm = new LoginStateMachine();
        StateChangedEventArgs? fired = null;
        sm.StateChanged += (_, e) => fired = e;

        Assert.True(sm.TransitionTo(AppState.Detecting, "网络恢复"));
        Assert.Equal(AppState.Detecting, sm.Current);
        Assert.NotNull(fired);
        Assert.Equal(AppState.Offline, fired!.From);
        Assert.Equal(AppState.Detecting, fired.To);
        Assert.Equal("网络恢复", fired.Reason);
    }

    [Fact]
    public void 非法迁移抛异常()
    {
        // 离线未检测不得直接认证
        var sm1 = new LoginStateMachine();
        Assert.Throws<InvalidOperationException>(() => sm1.TransitionTo(AppState.Authenticating, "跳过检测"));

        // 在线不得不经过检测直接认证
        var sm2 = new LoginStateMachine();
        sm2.TransitionTo(AppState.Detecting, "setup");
        sm2.TransitionTo(AppState.Online, "setup");
        Assert.Throws<InvalidOperationException>(() => sm2.TransitionTo(AppState.Authenticating, "在线直接认证"));

        // 认证后回到检测是允许的（复核场景）
        var sm3 = new LoginStateMachine();
        sm3.TransitionTo(AppState.Detecting, "setup");
        sm3.TransitionTo(AppState.Authenticating, "setup");
        Assert.True(sm3.TransitionTo(AppState.Detecting, "复核"));
    }

    [Fact]
    public void 同态迁移不触发事件但可更新原因()
    {
        var sm = new LoginStateMachine();
        sm.TransitionTo(AppState.Detecting, "第一次");
        StateChangedEventArgs? reasonFired = null;
        bool stateFired = false;
        sm.StateChanged += (_, _) => stateFired = true;
        sm.ReasonChanged += (_, e) => reasonFired = e;

        Assert.False(sm.TransitionTo(AppState.Detecting, "第二次"));
        Assert.False(stateFired);
        Assert.NotNull(reasonFired);
        Assert.Equal("第二次", reasonFired!.Reason);

        // 相同原因重复设置：完全无事件
        reasonFired = null;
        sm.TransitionTo(AppState.Detecting, "第二次");
        Assert.Null(reasonFired);
    }

    [Fact]
    public void 完整生命周期_离线检测认证在线掉线重检()
    {
        var sm = new LoginStateMachine();
        sm.TransitionTo(AppState.Detecting, "启动");
        sm.TransitionTo(AppState.Authenticating, "未认证");
        sm.TransitionTo(AppState.Online, "登录成功");
        sm.TransitionTo(AppState.Detecting, "心跳发现掉线");
        sm.TransitionTo(AppState.Authenticating, "重新登录");
        sm.TransitionTo(AppState.Online, "再次在线");
        sm.TransitionTo(AppState.Offline, "退出");
        Assert.Equal(AppState.Offline, sm.Current);
    }
}

public class RetryPolicyTests
{
    [Fact]
    public void 密码错误与验证码_不重试()
    {
        Assert.Null(RetryPolicy.NextDelay(AuthOutcome.PasswordError, attempt: 0));
        Assert.Null(RetryPolicy.NextDelay(AuthOutcome.CaptchaNeeded, attempt: 5));
    }

    [Fact]
    public void 门户不可达_固定30秒()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), RetryPolicy.NextDelay(AuthOutcome.PortalUnreachable, 0));
        Assert.Equal(TimeSpan.FromSeconds(30), RetryPolicy.NextDelay(AuthOutcome.NetworkOffline, 9));
    }

    [Fact]
    public void 未知失败_指数退避封顶60秒()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), RetryPolicy.NextDelay(AuthOutcome.UnknownFailure, 0));
        Assert.Equal(TimeSpan.FromSeconds(10), RetryPolicy.NextDelay(AuthOutcome.UnknownFailure, 1));
        Assert.Equal(TimeSpan.FromSeconds(20), RetryPolicy.NextDelay(AuthOutcome.UnknownFailure, 2));
        Assert.Equal(TimeSpan.FromSeconds(60), RetryPolicy.NextDelay(AuthOutcome.UnknownFailure, 3));
        Assert.Equal(TimeSpan.FromSeconds(60), RetryPolicy.NextDelay(AuthOutcome.UnknownFailure, 99));
    }

    [Fact]
    public void IP冲突_固定5分钟()
    {
        // RADIUS IP 冲突只能等旧会话释放，短间隔重试会反复失败并续命验证码惩罚
        Assert.Equal(TimeSpan.FromMinutes(5), RetryPolicy.NextDelay(AuthOutcome.IpConflict, 0));
        Assert.Equal(TimeSpan.FromMinutes(5), RetryPolicy.NextDelay(AuthOutcome.IpConflict, 9));
    }
}
