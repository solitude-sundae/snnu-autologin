using System.Threading.Channels;
using SnnuAutoLogin.Logging;
using SnnuAutoLogin.Security;

namespace SnnuAutoLogin.Core;

/// <summary>气泡通知类型。</summary>
public enum BalloonKind { Info, Success, Warning, Error }

/// <summary>UI 回调接口（由托盘实现；协调器不依赖任何 WinForms 类型，便于单测）。</summary>
public interface IUserNotify
{
    /// <summary>状态迁移通知（可能在后台线程触发，实现方自行封送到 UI 线程）。</summary>
    void OnStateChanged(AppState from, AppState to, string reason);

    /// <summary>气泡通知。clickAction："open-portal"（打开门户）/ "open-config"（打开配置），用户点击气泡时执行；null 无动作。</summary>
    void OnBalloon(string title, string message, BalloonKind kind, string? clickAction = null);

    /// <summary>请求打开配置窗口（未配置/密码错误场景）。</summary>
    void RequestConfigWindow(string reason);
}

/// <summary>
/// 认证协调器：串联 探测(generate_204 + 状态页双通道) → 状态机 → 登录 → 心跳 → 重试。
/// 所有触发源（启动/网络事件/心跳掉线/手动/重试定时）写入容量 1 的触发通道，
/// 由唯一的 worker 逐个消费——天然串行化、天然合并触发风暴，且不会丢失"检测期间的新触发"。
/// </summary>
public sealed class AppCoordinator : IDisposable
{
    private readonly ConfigStore _store;
    private readonly IUserNotify _notify;
    private readonly LoginStateMachine _state = new();

    // 容量 1、满则丢弃：一轮检测期间的重复触发至多沉淀为一次补检
    private readonly Channel<string> _triggers = Channel.CreateBounded<string>(
        new BoundedChannelOptions(1) { FullMode = BoundedChannelFullMode.DropWrite });

    private PortalClient _portal = null!;
    private DetectProber _prober = null!;
    private NetworkMonitor _network = null!;
    private AppConfig _config = null!;
    private KeywordSet _keywords = KeywordSet.Default;

    private CancellationTokenSource? _lifecycleCts;
    private Task? _workerTask;
    private PeriodicTimer? _heartbeatTimer;
    private Task? _heartbeatTask;
    private int _heartbeatTick;                    // 心跳计数（驱动外网探测节奏）
    private readonly FakeOnlineDetector _fakeOnline = new();
    private readonly Queue<DateTime> _fakeOnlineRecoveries = new(); // 自愈频率护栏
    private bool _fakeOnlinePaused;                // 护栏触发后暂停自愈（外网恢复时自动解除）
    private int _externalRecheckGeneration;        // 外网环境定期复查代号
    private int _unknownFailCount;                 // 未知失败指数退避计数
    // 熔断分级：PasswordError=严格熔断（仅改配置恢复）；CaptchaNeeded=暂停自动登录+周期观察自动恢复；null 正常
    private AuthOutcome? _haltReason;
    private CancellationTokenSource? _captchaWatchCts; // 验证码暂停期间的观察定时
    private bool _suffixMismatchWarned;            // 服务类型错配提醒只发一次，配置保存后重置
    private bool _disposed;

    public AppCoordinator(ConfigStore store, IUserNotify notify)
    {
        _store = store;
        _notify = notify;
        _state.StateChanged += (_, e) =>
        {
            Log.Info($"状态迁移: {e.From} → {e.To}（{e.Reason}）");
            _notify.OnStateChanged(e.From, e.To, e.Reason);
        };
    }

    public AppState CurrentState => _state.Current;
    public string CurrentReason => _state.CurrentReason;

    /// <summary>门户状态页 URL（"打开门户"菜单用）。</summary>
    public string PortalStatusUrl =>
        _portal?.StatusPageUrl ?? "http://202.117.144.205:8605/snnuportal/userstatus.jsp";

    public void Start()
    {
        if (_workerTask != null)
        {
            return;
        }
        _config = _store.Load();
        _keywords = _config.Keywords ?? KeywordSet.Default;
        var endpoints = _config.Endpoints ?? new PortalEndpoints();
        _portal = new PortalClient(endpoints, _keywords);
        _prober = new DetectProber();
        _lifecycleCts = new CancellationTokenSource();
        _network = new NetworkMonitor(reason =>
        {
            Log.Info($"网络事件: {reason}");
            TriggerCheck(reason);
        });

        _workerTask = Task.Run(() => WorkerLoopAsync(_lifecycleCts.Token));
        Log.Info($"程序启动 v{typeof(AppCoordinator).Assembly.GetName().Version}，配置目录: {_store.ConfigDirectory}");
        // 开机自启后立即排队首轮检测（满足"登录后 ≤5 秒完成首次检测"用例）
        TriggerCheck("程序启动");
    }

    /// <summary>触发一轮检测。任意线程可调；触发风暴自动合并。</summary>
    public void TriggerCheck(string reason)
    {
        if (_disposed)
        {
            return;
        }
        _triggers.Writer.TryWrite(reason);
    }

    /// <summary>配置保存后调用：解除熔断/验证码观察/假在线暂停并立即重检。</summary>
    public void OnConfigSaved()
    {
        _config = _store.Load();
        _keywords = _config.Keywords ?? KeywordSet.Default;
        _haltReason = null;
        StopCaptchaObservation();
        _fakeOnlinePaused = false;
        _suffixMismatchWarned = false;
        _unknownFailCount = 0;
        TriggerCheck("配置已更新");
    }

    private async Task WorkerLoopAsync(CancellationToken ct)
    {
        try
        {
            await foreach (var reason in _triggers.Reader.ReadAllAsync(ct))
            {
                try
                {
                    await RunCheckOnceAsync(reason);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Log.Error($"检测轮异常: {ex}");
                    _state.TransitionTo(AppState.Offline, $"内部错误: {ex.GetType().Name}");
                    ScheduleRetry(AuthOutcome.UnknownFailure);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // 程序退出
        }
    }

    /// <summary>单轮完整检测（双通道判定 + 按需登录）。迁移语义见 docs/02 状态机图。</summary>
    private async Task RunCheckOnceAsync(string triggerReason)
    {
        if (_disposed)
        {
            return;
        }
        if (_haltReason == AuthOutcome.PasswordError)
        {
            _state.TransitionTo(AppState.Offline, "已熔断：请在配置中修改账号密码");
            return;
        }
        if (_haltReason == AuthOutcome.CaptchaNeeded)
        {
            // 验证码暂停：等观察定时发现解除或已在线后自动恢复（见 StartCaptchaObservation）
            _state.TransitionTo(AppState.Offline, "已暂停：门户要求验证码，观察恢复中");
            return;
        }

        _state.TransitionTo(AppState.Detecting, triggerReason);
        var ct = _lifecycleCts!.Token;

        // 通道一：门户状态页（校园网内的权威判定）
        var probe = await _portal.ProbeStatusAsync(ct);
        switch (probe.Status)
        {
            case PortalStatus.Online:
            {
                var session = PortalResponseParser.ExtractSession(probe.Html ?? string.Empty);
                await EnterOnlineAsync(session, alreadyOnline: true, ct);
                return;
            }
            case PortalStatus.Unauthenticated:
            {
                // 保存离线样本（docs/01 §5 待实测项的自动捕获机制）
                SaveCapture("status_unauth", probe.Html);
                if (!_config.IsConfigured)
                {
                    _state.TransitionTo(AppState.Offline, "未配置账号");
                    _notify.RequestConfigWindow("首次使用请配置学号与密码");
                    return;
                }
                await AuthenticateAsync(ct);
                return;
            }
            default:
            {
                // 通道二：门户不可达 → generate_204 判断是否其他可直连网络（家庭 WiFi 等）
                bool direct = await _prober.IsDirectInternetAsync(ct);
                if (direct)
                {
                    await EnterOnlineAsync(session: null, alreadyOnline: true, ct, externalNetwork: true);
                }
                else
                {
                    _state.TransitionTo(AppState.Offline, "无网络或门户不可达");
                    ScheduleRetry(AuthOutcome.NetworkOffline);
                }
                return;
            }
        }
    }

    /// <summary>认证子流程：验证码检查 → POST 登录 → 结果分发。</summary>
    private async Task AuthenticateAsync(CancellationToken ct)
    {
        _state.TransitionTo(AppState.Authenticating, "提交登录");
        var (reachable, loginPageHtml) = await _portal.GetLoginPageAsync(ct);
        if (reachable && !string.IsNullOrEmpty(loginPageHtml))
        {
            SaveCapture("login_page_form", loginPageHtml);
            if (PortalResponseParser.ClassifyLoginResponse(loginPageHtml, _keywords) == AuthOutcome.CaptchaNeeded)
            {
                HaltForCaptcha();
                return;
            }
        }

        var password = ConfigStore.DecryptPassword(_config);
        if (password == null)
        {
            HaltForManualAction(AuthOutcome.PasswordError, "密码解密失败，请重新配置", "密码读取失败",
                "本地保存的密码无法解密（可能复制自其他电脑），请重新输入。", "open-config");
            return;
        }

        var (outcome, responseHtml) = await _portal.LoginAsync(
            new LoginRequest(_config.StudentId, password, _config.ServiceSuffix), ct);
        if (!string.IsNullOrEmpty(responseHtml))
        {
            SaveCapture($"login_resp_{outcome}", responseHtml);
        }
        Log.Info($"登录结果: {outcome} (账号 {Log.Mask(_config.FullAccount)})");

        switch (outcome)
        {
            case AuthOutcome.Success:
            case AuthOutcome.AlreadyOnline:
            {
                // 实测（2026-09-23 采样）：登录成功时门户直接回"在线状态页"，且 IP 会话生效存在
                // 数秒延迟——立即复核会撞上延迟而误报失败。故响应本身已是状态页时直接进在线态，
                // 由心跳兜底；仅"命中成功关键字但响应不是状态页"时才做复核。
                if (!string.IsNullOrEmpty(responseHtml) && PortalResponseParser.LooksOnline(responseHtml, _keywords))
                {
                    var session = PortalResponseParser.ExtractSession(responseHtml);
                    await EnterOnlineAsync(session, alreadyOnline: false, ct);
                    return;
                }
                var verify = await _portal.ProbeStatusAsync(ct);
                if (verify.Status == PortalStatus.Online)
                {
                    var session = PortalResponseParser.ExtractSession(verify.Html ?? string.Empty);
                    await EnterOnlineAsync(session, alreadyOnline: outcome == AuthOutcome.AlreadyOnline, ct);
                    return;
                }
                Log.Warn("登录响应判成功但状态页复核未在线，按未知失败退避");
                _state.TransitionTo(AppState.Offline, "登录后复核未在线");
                ScheduleRetry(AuthOutcome.UnknownFailure);
                return;
            }
            case AuthOutcome.PasswordError:
            {
                _haltReason = AuthOutcome.PasswordError;
                StopCaptchaObservation();
                _unknownFailCount = 0;
                _state.TransitionTo(AppState.Offline, "账号或密码错误（已停止重试）");
                _notify.OnBalloon("登录失败", "账号或密码错误，已停止自动重试，请检查配置（点击气泡打开）。", BalloonKind.Error, "open-config");
                _notify.RequestConfigWindow("账号或密码错误");
                return;
            }
            case AuthOutcome.CaptchaNeeded:
            {
                HaltForCaptcha();
                return;
            }
            case AuthOutcome.PortalUnreachable:
            {
                _state.TransitionTo(AppState.Offline, "门户请求超时");
                ScheduleRetry(AuthOutcome.PortalUnreachable);
                return;
            }
            default:
            {
                _state.TransitionTo(AppState.Offline, $"登录未成功（{outcome}），将退避重试");
                ScheduleRetry(AuthOutcome.UnknownFailure);
                return;
            }
        }
    }

    /// <summary>密码错误等严重凭证问题：严格熔断（仅改配置恢复）。</summary>
    private void HaltForManualAction(AuthOutcome reason, string stateReason, string title, string message, string? clickAction)
    {
        _haltReason = reason;
        StopCaptchaObservation();
        _state.TransitionTo(AppState.Offline, stateReason);
        _notify.OnBalloon(title, message, BalloonKind.Error, clickAction);
        _notify.RequestConfigWindow(title);
    }

    /// <summary>
    /// 验证码暂停：不再自动尝试（防锁定），但不锁死——启动 5 分钟周期观察：
    /// 发现已在线（用户已在浏览器手动登录）或门户验证码解除，即自动恢复自动认证。
    /// 气泡指引"点击打开登录页手动登录一次"，无需打开配置窗口。
    /// </summary>
    private void HaltForCaptcha()
    {
        _haltReason = AuthOutcome.CaptchaNeeded;
        _state.TransitionTo(AppState.Offline, "门户要求验证码，已暂停自动登录");
        _notify.OnBalloon("需要验证码",
            "门户要求输入验证码，已暂停自动登录。点击本气泡打开登录页，手动登录一次后程序会自动恢复。",
            BalloonKind.Warning, "open-portal");
        StartCaptchaObservation();
    }

    private void StartCaptchaObservation()
    {
        StopCaptchaObservation();
        var cts = new CancellationTokenSource();
        _captchaWatchCts = cts;
        _ = Task.Run(async () =>
        {
            try
            {
                while (!cts.IsCancellationRequested && _haltReason == AuthOutcome.CaptchaNeeded && !_disposed)
                {
                    await Task.Delay(TimeSpan.FromMinutes(5), cts.Token);
                    if (_disposed || _haltReason != AuthOutcome.CaptchaNeeded)
                    {
                        return;
                    }
                    // 观察一：用户是否已在浏览器手动登录成功
                    var probe = await _portal.ProbeStatusAsync(cts.Token);
                    if (probe.Status == PortalStatus.Online)
                    {
                        Log.Info("验证码观察：发现已在线（可能已手动登录），自动恢复");
                        _haltReason = null;
                        TriggerCheck("验证码观察恢复");
                        return;
                    }
                    // 观察二：门户验证码是否已解除（冷却结束）
                    var (reachable, loginHtml) = await _portal.GetLoginPageAsync(cts.Token);
                    if (reachable && !string.IsNullOrEmpty(loginHtml) &&
                        PortalResponseParser.ClassifyLoginResponse(loginHtml, _keywords) != AuthOutcome.CaptchaNeeded)
                    {
                        Log.Info("验证码观察：登录页验证码已解除，自动恢复");
                        _haltReason = null;
                        TriggerCheck("验证码观察恢复");
                        return;
                    }
                    Log.Debug("验证码观察：验证码仍在，继续等待");
                }
            }
            catch (OperationCanceledException) { /* 恢复或退出 */ }
            catch (Exception ex)
            {
                Log.Error($"验证码观察异常: {ex.Message}");
            }
        });
    }

    private void StopCaptchaObservation()
    {
        _captchaWatchCts?.Cancel();
        _captchaWatchCts?.Dispose();
        _captchaWatchCts = null;
    }

    /// <summary>
    /// 服务类型错配提醒：状态页显示本学号在 X 通道在线，但配置选了 Y——
    /// 这种错配会在下次掉线重登时反复失败并触发门户验证码（实测案例 2026-09-28）。
    /// 只在每次进入在线态时提醒一次；别人的会话（如宿舍路由器）不打扰。
    /// </summary>
    private void CheckServiceSuffixMismatch(PortalSessionInfo? session)
    {
        if (session == null || _suffixMismatchWarned || !_config.IsConfigured)
        {
            return;
        }
        var verdict = AccountMatcher.Match(session.Account, _config.StudentId, _config.ServiceSuffix);
        if (verdict == AccountVerdict.Match)
        {
            _suffixMismatchWarned = false;
            return;
        }
        if (verdict != AccountVerdict.SuffixMismatch)
        {
            return;
        }
        _suffixMismatchWarned = true;
        var actual = AccountMatcher.SuffixOf(session.Account);
        var actualName = string.IsNullOrEmpty(actual) ? "校园网免费通道" : ServiceTypes.DisplayNameOf(actual);
        Log.Warn($"服务类型疑似配错：在线通道为 {actualName}，配置为 {ServiceTypes.DisplayNameOf(_config.ServiceSuffix)}");
        _notify.OnBalloon("服务类型可能配错",
            $"检测到你的账号实际在「{actualName}」在线，但配置选的是「{ServiceTypes.DisplayNameOf(_config.ServiceSuffix)}」。配置不一致会在下次掉线时登录失败，建议修改（点击气泡打开配置）。",
            BalloonKind.Warning, "open-config");
    }

    /// <summary>进入在线态：启动心跳（仅校园网门户在线才需要）并通知 UI。</summary>
    private async Task EnterOnlineAsync(PortalSessionInfo? session, bool alreadyOnline, CancellationToken ct, bool externalNetwork = false)
    {
        _unknownFailCount = 0;
        if (externalNetwork)
        {
            StopHeartbeat();
            _state.TransitionTo(AppState.Online, "非校园网环境（直连可用）");
            ScheduleExternalRecheck();
            return;
        }

        StartHeartbeat();
        if (alreadyOnline)
        {
            _state.TransitionTo(AppState.Online, session != null ? $"已在线：{Log.Mask(session.Account)}" : "已在线");
            CheckServiceSuffixMismatch(session);
            return;
        }

        // 刚登录成功：查询剩余流量丰富气泡信息
        var fluxText = string.Empty;
        if (session?.Ip != null)
        {
            var flux = await _portal.GetFluxAsync(session.Ip, session.Account, ct);
            if (flux != null)
            {
                fluxText = $"，剩余流量 {flux.FreeMb:0.##} MB";
            }
        }
        _state.TransitionTo(AppState.Online, $"登录成功{fluxText}");
        _notify.OnBalloon("校园网已连接", $"自动登录成功{fluxText}。", BalloonKind.Success);
    }

    /// <summary>按策略安排静默重试。触发通道容量 1 自然合并重复的定时触发。</summary>
    private void ScheduleRetry(AuthOutcome failure)
    {
        var delay = RetryPolicy.NextDelay(failure, _unknownFailCount);
        if (delay == null)
        {
            return; // 熔断类（密码错误/验证码）由调用方负责，不应走到这里
        }
        if (failure == AuthOutcome.UnknownFailure)
        {
            _unknownFailCount++;
        }
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay.Value, _lifecycleCts!.Token);
                if (!_disposed)
                {
                    Log.Info($"重试定时触发 (延迟 {delay.Value.TotalSeconds:0}s)");
                    TriggerCheck("重试定时");
                }
            }
            catch (TaskCanceledException) { /* 程序退出 */ }
        });
    }

    #region 心跳（双通道：门户状态页 + 假在线检测）

    private void StartHeartbeat()
    {
        StopHeartbeat();
        var interval = TimeSpan.FromSeconds(Math.Max(15, _config.HeartbeatSeconds));
        _heartbeatTick = 0;
        _fakeOnline.Reset();
        _heartbeatTimer = new PeriodicTimer(interval);
        _heartbeatTask = Task.Run(async () =>
        {
            try
            {
                while (await _heartbeatTimer.WaitForNextTickAsync(_lifecycleCts!.Token))
                {
                    if (_state.Current != AppState.Online)
                    {
                        continue; // 认证过程中的抖动不触发
                    }

                    // 通道一：门户状态页（捕获会话被下线/被踢）
                    var probe = await _portal.ProbeStatusAsync(_lifecycleCts.Token);
                    if (probe.Status != PortalStatus.Online)
                    {
                        Log.Warn("心跳发现状态页异常，触发重新检测");
                        StopHeartbeat();
                        _state.TransitionTo(AppState.Offline, "心跳发现掉线");
                        TriggerCheck("心跳发现掉线");
                        break;
                    }

                    // 通道二：外网真实性（假在线检测，门户会说谎但 generate_204 不会）
                    _heartbeatTick++;
                    if (!_fakeOnline.ShouldProbeThisTick(_heartbeatTick))
                    {
                        continue;
                    }
                    bool direct = await _prober.IsDirectInternetAsync(_lifecycleCts.Token);
                    var verdict = _fakeOnline.Record(direct);
                    if (verdict == FakeOnlineVerdict.Healthy && _fakeOnlinePaused)
                    {
                        _fakeOnlinePaused = false;
                        Log.Info("外网探测恢复，假在线自愈重新就绪");
                    }
                    else if (verdict == FakeOnlineVerdict.InsufficientEvidence)
                    {
                        Log.Warn("假在线嫌疑：门户显示在线但外网探测失败");
                    }
                    else if (verdict == FakeOnlineVerdict.FakeOnline)
                    {
                        if (_fakeOnlinePaused)
                        {
                            // 自愈暂停期间假在线仍在持续：转灰色 + 10 分钟观察复查，
                            // 外网探测恢复即自动解除暂停（见 ScheduleFakeOnlineObservation）
                            Log.Warn("假在线持续（自愈已暂停，转入观察复查）");
                            StopHeartbeat();
                            _state.TransitionTo(AppState.Offline, "假在线持续（自愈暂停中）");
                            ScheduleFakeOnlineObservation();
                            return;
                        }
                        await RecoverFromFakeOnlineAsync(_lifecycleCts.Token);
                        return; // 自愈流程成功后会自行重启心跳
                    }
                }
            }
            catch (OperationCanceledException) { /* 程序退出 */ }
            catch (ObjectDisposedException) { /* 心跳被重启（StopHeartbeat 卸掉正在等待的 timer），正常 */ }
            catch (Exception ex)
            {
                Log.Error($"心跳任务异常: {ex.Message}");
            }
        });
    }

    /// <summary>
    /// 假在线自愈：门户说在线但外网持续不通（联通代拨出口会话被老化）。
    /// 下线说谎的旧会话 → 等网关确认下线（会话生效有 5~10s 延迟）→ 重新登录重建出口隧道。
    /// 注：此方法运行在心跳任务上而非 worker 通道，理论上有与手动检测并发的可能；
    /// 同一 IP/账号的重复 POST 对门户幂等，状态机有锁保护，可接受。
    /// </summary>
    private async Task RecoverFromFakeOnlineAsync(CancellationToken ct)
    {
        if (!TryBeginFakeOnlineRecovery())
        {
            // 护栏：30 分钟内已自愈 3 次仍假在线 → 停止自愈（疑似套餐/线路问题）。
            // 不能就此停摆（否则只能靠网络事件/手动才会再动）：转观察复查，外网恢复自动解除暂停
            _fakeOnlinePaused = true;
            Log.Error("假在线自愈次数超限（30 分钟 3 次），暂停自动恢复，转入观察复查");
            StopHeartbeat();
            _state.TransitionTo(AppState.Offline, "反复假在线，已暂停自愈");
            _notify.OnBalloon("网络异常",
                "外网持续不通，自动重连多次未解决。请检查运营商套餐/余额，或联系网络中心 029-85310558。",
                BalloonKind.Error);
            ScheduleFakeOnlineObservation();
            return;
        }

        Log.Warn("判定假在线：下线旧会话并重新登录");
        StopHeartbeat();
        _state.TransitionTo(AppState.Detecting, "假在线：外网不通");
        await _portal.LogoffAsync(ct);
        // 轮询等待下线生效（最多 ~10s），确认后立即重登；门户不可达时也直接走登录
        for (var i = 0; i < 5; i++)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
            var status = await _portal.ProbeStatusAsync(ct);
            if (status.Status is PortalStatus.Unauthenticated or PortalStatus.Unreachable)
            {
                break;
            }
        }
        await AuthenticateAsync(ct);
    }

    /// <summary>自愈频率护栏：30 分钟滑动窗口内最多 3 次，防止死循环反复断网。</summary>
    private bool TryBeginFakeOnlineRecovery()
    {
        var now = DateTime.Now;
        while (_fakeOnlineRecoveries.Count > 0 &&
               (now - _fakeOnlineRecoveries.Peek()).TotalMinutes > 30)
        {
            _fakeOnlineRecoveries.Dequeue();
        }
        if (_fakeOnlineRecoveries.Count >= 3)
        {
            return false;
        }
        _fakeOnlineRecoveries.Enqueue(now);
        return true;
    }

    private void StopHeartbeat()
    {
        _heartbeatTimer?.Dispose();
        _heartbeatTimer = null;
        _heartbeatTask = null;
    }

    /// <summary>
    /// 假在线暂停期间的观察复查（10 分钟）：恢复在线监护与外网探测——
    /// 外网探测恢复即解除暂停；真掉线则走正常重登；持续假在线则回到暂停态继续观察。
    /// </summary>
    private void ScheduleFakeOnlineObservation()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(10), _lifecycleCts!.Token);
                if (!_disposed && _fakeOnlinePaused)
                {
                    Log.Info("假在线观察复查");
                    TriggerCheck("假在线观察复查");
                }
            }
            catch (TaskCanceledException) { /* 程序退出 */ }
        });
    }

    /// <summary>
    /// 非校园网环境（家庭 WiFi 等）无门户可监护，改用 5 分钟一次的轻量复查：
    /// 若期间切回校园网（网络事件可能丢失，如跨网段漫游），复查会发现门户并按需登录。
    /// </summary>
    private void ScheduleExternalRecheck()
    {
        var generation = ++_externalRecheckGeneration;
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromMinutes(5), _lifecycleCts!.Token);
                if (generation == Volatile.Read(ref _externalRecheckGeneration) &&
                    !_disposed && _state.Current == AppState.Online)
                {
                    TriggerCheck("外网环境定期复查");
                }
            }
            catch (TaskCanceledException) { /* 程序退出 */ }
        });
    }

    #endregion

    /// <summary>保存门户响应捕获（供接口文档实测核对；门户响应不含密码，可安全落盘）。</summary>
    private void SaveCapture(string name, string? html)
    {
        if (string.IsNullOrEmpty(html))
        {
            return;
        }
        try
        {
            var dir = _store.CapturesDirectory;
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, $"{DateTime.Now:yyyyMMdd_HHmmss}_{name}.html");
            File.WriteAllText(file, html);
            // 只留最近 20 个捕获文件，防膨胀
            foreach (var old in Directory.EnumerateFiles(dir, "*.html")
                         .OrderByDescending(f => f)
                         .Skip(20))
            {
                try { File.Delete(old); } catch { /* 忽略 */ }
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"保存捕获失败: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _triggers.Writer.TryComplete();
        _lifecycleCts?.Cancel();
        _network?.Dispose();
        StopHeartbeat();
        StopCaptchaObservation();
        try { _workerTask?.Wait(TimeSpan.FromSeconds(2)); } catch { /* 忽略退出超时 */ }
        _portal?.Dispose();
        _prober?.Dispose();
        _lifecycleCts?.Dispose();
    }
}
