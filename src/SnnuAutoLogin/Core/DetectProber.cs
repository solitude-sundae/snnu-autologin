using System.Net.Http;
using System.Net.Sockets;

namespace SnnuAutoLogin.Core;

/// <summary>
/// 直连互联网探测（captive portal 检测第一通道）。
/// 三种探测并行、3 秒超时、任一命中即认为可直连：
///   1. 小米 generate_204：返回 204 No Content 即直连；
///   2. 微软 connecttest.txt：正文恰为 "Microsoft Connect Test" 即直连；
///   3. **免 DNS 的 TCP 直连**（223.5.5.5:443 / 119.29.29.29:443）：能建连即说明出口通。
/// 未认证校园网内会被网关劫持（返回门户页/非 204），据此与门户状态页组成双通道判定。
/// 第 3 项是假在线误报的防线：校园网 DNS 抖动时前两项会失败，但真实外网其实可用，
/// 若据此判定"假在线"并执行下线重登，会反复拆卸会话、把运营商 RADIUS 打成 IP 冲突
/// （实测事故 2026-11-19：21:32/21:44/22:41/22:52 四次误判自愈后出现 Rad:IP conflict）。
/// </summary>
public sealed class DetectProber : IDisposable
{
    private const int ProbeTimeoutSeconds = 3;

    private static readonly (string Url, string? ExpectBody)[] Probes =
    {
        ("http://connect.rom.miui.com/generate_204", null),
        ("http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"),
    };

    /// <summary>免 DNS 的公网 TCP 探测点（阿里 DNS / 腾讯 DNS 的 443 端口）。</summary>
    private static readonly (string Host, int Port)[] TcpProbes =
    {
        ("223.5.5.5", 443),
        ("119.29.29.29", 443),
    };

    private readonly HttpClient _http;

    public DetectProber(HttpMessageHandler? handler = null)
    {
        _http = handler == null
            ? new HttpClient(new HttpClientHandler { UseProxy = false }, disposeHandler: true)
            : new HttpClient(handler, disposeHandler: false);
        _http.Timeout = TimeSpan.FromSeconds(ProbeTimeoutSeconds);
    }

    /// <summary>返回 true 表示可直连互联网（家庭 WiFi / 已认证校园网 / 出口真实可用）。</summary>
    public async Task<bool> IsDirectInternetAsync(CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(ProbeTimeoutSeconds));
        try
        {
            var tasks = Probes.Select(p => ProbeOneAsync(p.Url, p.ExpectBody, cts.Token))
                .Concat(TcpProbes.Select(p => ProbeTcpAsync(p.Host, p.Port, cts.Token)))
                .ToList();
            var all = Task.WhenAll(tasks);
            try
            {
                await all.WaitAsync(TimeSpan.FromSeconds(ProbeTimeoutSeconds + 1), ct);
            }
            catch (TimeoutException)
            {
                // 探测点整体超时（网络栈异常），按不可直连处理
            }
            return tasks.Any(t => t.IsCompletedSuccessfully && t.Result);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    private async Task<bool> ProbeOneAsync(string url, string? expectBody, CancellationToken ct)
    {
        try
        {
            using var resp = await _http.GetAsync(url, HttpCompletionOption.ResponseContentRead, ct);
            if (expectBody == null)
            {
                return (int)resp.StatusCode == 204;
            }
            var body = await resp.Content.ReadAsStringAsync(ct);
            return (int)resp.StatusCode == 200 &&
                   body.Trim().Equals(expectBody, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException or TimeoutException)
        {
            return false;
        }
    }

    /// <summary>免 DNS：直接对公网 IP 建 TCP 连接。未认证时网关会阻断/重定向，建连失败。</summary>
    private static async Task<bool> ProbeTcpAsync(string host, int port, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(System.Net.IPAddress.Parse(host), port, ct);
            return client.Connected;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or TaskCanceledException
                                       or TimeoutException or ArgumentException or FormatException)
        {
            return false;
        }
    }

    public void Dispose() => _http.Dispose();
}
