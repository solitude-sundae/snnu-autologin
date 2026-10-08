using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using SnnuAutoLogin.Core;
using SnnuAutoLogin.Logging;
using SnnuAutoLogin.Security;

namespace SnnuAutoLogin.Ui;

/// <summary>
/// 托盘应用主上下文：NotifyIcon + 右键菜单 + 状态图标 + 气泡。
/// 实现 <see cref="IUserNotify"/>，把协调器的后台线程回调封送到 UI 线程。
/// 图标为运行时 GDI+ 绘制（免资源文件），四态四色 + 熔断红。
/// </summary>
internal sealed class TrayContext : ApplicationContext, IUserNotify
{
    private readonly NotifyIcon _tray;
    private readonly ConfigStore _store;
    private readonly AppCoordinator _coordinator;
    private readonly SynchronizationContext _ui;
    private readonly Dictionary<AppState, Icon> _icons;
    private readonly ToolStripMenuItem _autoStartItem;
    private ConfigForm? _configForm;
    private string? _pendingBalloonAction; // 最近一次气泡携带的点击动作（open-portal / open-config）

    public TrayContext(ConfigStore store)
    {
        _store = store;
        _ui = SynchronizationContext.Current ?? new SynchronizationContext();
        _icons = BuildIcons();
        // 先构造协调器（不触发回调），托盘就绪后再 Start()
        _coordinator = new AppCoordinator(store, this);

        var menu = new ContextMenuStrip();
        var checkNow = new ToolStripMenuItem("立即检测", null, (_, _) => _coordinator.TriggerCheck("手动触发"));
        var config = new ToolStripMenuItem("配置…", null, (_, _) => ShowConfigForm("手动打开"));
        _autoStartItem = new ToolStripMenuItem("开机自启动", null, (_, _) => ToggleAutoStart())
        {
            Checked = AutoStartManager.IsEnabled(),
        };
        var portal = new ToolStripMenuItem("打开门户状态页", null, (_, _) => OpenPortal());
        var logs = new ToolStripMenuItem("打开日志目录", null, (_, _) => OpenLogs());
        var exit = new ToolStripMenuItem("退出", null, (_, _) => ExitApp());
        menu.Items.AddRange(new ToolStripItem[]
        {
            checkNow, config, new ToolStripSeparator(), _autoStartItem,
            new ToolStripSeparator(), portal, logs, new ToolStripSeparator(), exit,
        });

        _tray = new NotifyIcon
        {
            Icon = _icons[AppState.Offline],
            Text = "陕师大校园网自动认证",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _tray.DoubleClick += (_, _) => ShowConfigForm("托盘双击");
        _tray.BalloonTipClicked += (_, _) =>
        {
            var action = _pendingBalloonAction;
            _pendingBalloonAction = null;
            switch (action)
            {
                case "open-portal":
                    OpenPortal();
                    break;
                case "open-config":
                    ShowConfigForm("气泡点击");
                    break;
            }
        };

        _coordinator.Start();
    }

    #region IUserNotify（后台线程 → UI 线程封送）

    void IUserNotify.OnStateChanged(AppState from, AppState to, string reason)
    {
        _ui.Post(_ =>
        {
            if (!_icons.TryGetValue(to, out var icon))
            {
                return;
            }
            _tray.Icon = icon;
            _tray.Text = Truncate($"[{StateName(to)}] {reason}", 63);
        }, null);
    }

    void IUserNotify.OnBalloon(string title, string message, BalloonKind kind, string? clickAction)
    {
        _ui.Post(_ =>
        {
            var tipIcon = kind switch
            {
                BalloonKind.Success => ToolTipIcon.Info,
                BalloonKind.Warning => ToolTipIcon.Warning,
                BalloonKind.Error => ToolTipIcon.Error,
                _ => ToolTipIcon.None,
            };
            _pendingBalloonAction = clickAction;
            _tray.ShowBalloonTip(6000, title, message, tipIcon);
        }, null);
    }

    void IUserNotify.RequestConfigWindow(string reason)
    {
        _ui.Post(_ => ShowConfigForm(reason), null);
    }

    #endregion

    private void ShowConfigForm(string reason)
    {
        if (_configForm is { IsDisposed: false })
        {
            _configForm.Activate();
            return;
        }
        Log.Info($"打开配置窗口: {reason}");
        _configForm = new ConfigForm(_store, _coordinator);
        _configForm.Show();
    }

    private void ToggleAutoStart()
    {
        var target = !_autoStartItem.Checked;
        bool ok = AutoStartManager.SetEnabled(target);
        _autoStartItem.Checked = AutoStartManager.IsEnabled();
        if (!ok)
        {
            _tray.ShowBalloonTip(3000, "开机自启动", "设置自启动失败，请检查注册表权限。", ToolTipIcon.Warning);
        }
    }

    private void OpenPortal()
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = _coordinator.PortalStatusUrl,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            Log.Warn($"打开门户失败: {ex.Message}");
        }
    }

    private void OpenLogs()
    {
        try
        {
            var dir = Path.Combine(_store.ConfigDirectory, "logs");
            Directory.CreateDirectory(dir);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            Log.Warn($"打开日志目录失败: {ex.Message}");
        }
    }

    private void ExitApp()
    {
        _tray.Visible = false;
        _tray.Dispose();
        _coordinator.Dispose();
        ExitThread();
    }

    private static string StateName(AppState s) => s switch
    {
        AppState.Offline => "离线",
        AppState.Detecting => "检测中",
        AppState.Authenticating => "认证中",
        AppState.Online => "在线",
        _ => s.ToString(),
    };

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    /// <summary>绘制四态图标：灰(离线)/蓝(检测中)/黄(认证中)/绿(在线)；熔断时复用灰色并在气泡说明。</summary>
    private static Dictionary<AppState, Icon> BuildIcons()
    {
        Icon Draw(Color color, string glyph)
        {
            using var bmp = new Bitmap(32, 32);
            using var g = Graphics.FromImage(bmp);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using var fill = new SolidBrush(color);
            using var rim = new Pen(Color.White, 3f);
            g.FillEllipse(fill, 3, 3, 26, 26);
            g.DrawEllipse(rim, 3, 3, 26, 26);
            if (!string.IsNullOrEmpty(glyph))
            {
                using var font = new Font("Segoe UI", 13f, FontStyle.Bold, GraphicsUnit.Pixel);
                var size = g.MeasureString(glyph, font);
                g.DrawString(glyph, font, Brushes.White, (32 - size.Width) / 2f, (32 - size.Height) / 2f);
            }
            return Icon.FromHandle(bmp.GetHicon());
        }

        return new Dictionary<AppState, Icon>
        {
            [AppState.Offline] = Draw(Color.FromArgb(120, 120, 120), "!"),
            [AppState.Detecting] = Draw(Color.FromArgb(41, 128, 185), "?"),
            [AppState.Authenticating] = Draw(Color.FromArgb(230, 160, 20), "…"),
            [AppState.Online] = Draw(Color.FromArgb(39, 174, 96), "√"),
        };
    }
}
