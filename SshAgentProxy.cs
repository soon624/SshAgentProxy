using System.Diagnostics;
using SshAgentProxy.Pipes;
using SshAgentProxy.Protocol;

namespace SshAgentProxy;

public class SshAgentProxyService : IAsyncDisposable
{
    private readonly Config _config;
    private readonly NamedPipeAgentServer _server;
    private string _currentAgent;
    private readonly Dictionary<string, string> _keyToAgent = new(); // fingerprint -> agent name

    public event Action<string>? OnLog;
    public string CurrentAgent => _currentAgent;

    public SshAgentProxyService(Config config)
    {
        _config = config;
        _currentAgent = config.DefaultAgent;
        _server = new NamedPipeAgentServer(config.ProxyPipeName, HandleRequestAsync);
        _server.OnLog += msg => OnLog?.Invoke(msg);

        // 設定からキーマッピングを読み込み
        foreach (var mapping in config.KeyMappings)
        {
            if (!string.IsNullOrEmpty(mapping.Fingerprint))
                _keyToAgent[mapping.Fingerprint] = mapping.Agent;
            if (!string.IsNullOrEmpty(mapping.Comment))
                _keyToAgent[$"comment:{mapping.Comment}"] = mapping.Agent;
        }
    }

    public Task StartAsync(CancellationToken ct = default)
    {
        Log($"Starting proxy on pipe: {_config.ProxyPipeName}");
        Log($"Backend pipe: {_config.BackendPipeName}");
        Log($"Default agent: {_currentAgent}");

        _server.Start();
        Log("Proxy server started");
        Log("");
        Log("=== IMPORTANT ===");
        Log($"Set environment variable: SSH_AUTH_SOCK=\\\\.\\pipe\\{_config.ProxyPipeName}");
        Log("=================");

        return Task.CompletedTask;
    }

    private async Task<NamedPipeAgentClient?> ConnectToBackendAsync(CancellationToken ct = default)
    {
        var client = new NamedPipeAgentClient(_config.BackendPipeName);

        if (await client.TryConnectAsync(2000, ct))
        {
            Log($"Connected to backend: {_config.BackendPipeName}");
            return client;
        }

        Log($"Failed to connect to backend: {_config.BackendPipeName}");
        client.Dispose();
        return null;
    }

    public Task ForceSwitchToAsync(string agentName, CancellationToken ct = default)
    {
        // 強制切り替え（現在のagent状態を無視）
        _currentAgent = agentName == "1Password" ? "Bitwarden" : "1Password";
        return SwitchToAsync(agentName, ct);
    }

    public async Task SwitchToAsync(string agentName, CancellationToken ct = default)
    {
        if (_currentAgent == agentName)
        {
            Log($"Already using {agentName}");
            return;
        }

        Log($"Switching from {_currentAgent} to {agentName}...");

        var (primary, secondary) = agentName == "1Password"
            ? (_config.Agents.OnePassword, _config.Agents.Bitwarden)
            : (_config.Agents.Bitwarden, _config.Agents.OnePassword);

        // 1. ヘルパープロセスを終了（パイプを解放させる）
        await KillProcessAsync(primary.ProcessName);
        await KillProcessAsync(secondary.ProcessName);
        await Task.Delay(1000, ct);

        // 2. プライマリを先に起動（pipeを取得）
        StartProcessIfNeeded(primary.ProcessName, primary.ExePath);
        await Task.Delay(3000, ct); // 起動を待つ

        // 3. セカンダリを起動
        StartProcessIfNeeded(secondary.ProcessName, secondary.ExePath);
        await Task.Delay(1000, ct);

        _currentAgent = agentName;
        Log($"Switched to {agentName}");
    }

    private async Task<SshAgentMessage> HandleRequestAsync(SshAgentMessage request, CancellationToken ct)
    {
        return request.Type switch
        {
            SshAgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES => await HandleRequestIdentitiesAsync(ct),
            SshAgentMessageType.SSH_AGENTC_SIGN_REQUEST => await HandleSignRequestAsync(request.Payload, ct),
            _ => await ForwardRequestAsync(request, ct),
        };
    }

    private async Task<SshAgentMessage> HandleRequestIdentitiesAsync(CancellationToken ct)
    {
        Log("Request: List identities");

        using var client = await ConnectToBackendAsync(ct);
        if (client == null)
            return SshAgentMessage.Failure();

        try
        {
            var identities = await client.RequestIdentitiesAsync(ct);
            Log($"  Found {identities.Count} keys from {_currentAgent}");

            foreach (var id in identities)
            {
                Log($"    - {id.Comment} ({id.Fingerprint})");
            }

            return SshAgentMessage.IdentitiesAnswer(identities);
        }
        catch (Exception ex)
        {
            Log($"  Error: {ex.Message}");
            return SshAgentMessage.Failure();
        }
    }

    private async Task<SshAgentMessage> HandleSignRequestAsync(ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        var (keyBlob, data, flags) = SshAgentProtocol.ParseSignRequest(payload);
        var fingerprint = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(keyBlob))[..16];

        Log($"Request: Sign with key {fingerprint}");

        // キーマッピングがあれば、そのagentに切り替え
        if (_keyToAgent.TryGetValue(fingerprint, out var mappedAgent))
        {
            Log($"  Key mapped to {mappedAgent}, switching...");
            await ForceSwitchToAsync(mappedAgent, ct);

            var signature = await TrySignAsync(keyBlob, data, flags, ct);
            if (signature != null)
            {
                Log($"  Signed by {mappedAgent}");
                return SshAgentMessage.SignResponse(signature);
            }
        }

        // まず現在のバックエンドで試す
        Log($"  Trying current backend...");
        var sig = await TrySignAsync(keyBlob, data, flags, ct);
        if (sig != null)
        {
            Log($"  Signed successfully");
            return SshAgentMessage.SignResponse(sig);
        }

        // 失敗した場合、1Passwordに切り替えて試す
        Log($"  Sign failed, switching to 1Password...");
        await ForceSwitchToAsync("1Password", ct);

        sig = await TrySignAsync(keyBlob, data, flags, ct);
        if (sig != null)
        {
            _keyToAgent[fingerprint] = "1Password";
            Log($"  Signed by 1Password (mapping saved)");
            return SshAgentMessage.SignResponse(sig);
        }

        // まだ失敗なら、Bitwardenに切り替えて試す
        Log($"  Sign failed, switching to Bitwarden...");
        await ForceSwitchToAsync("Bitwarden", ct);

        sig = await TrySignAsync(keyBlob, data, flags, ct);
        if (sig != null)
        {
            _keyToAgent[fingerprint] = "Bitwarden";
            Log($"  Signed by Bitwarden (mapping saved)");
            return SshAgentMessage.SignResponse(sig);
        }

        Log("  Sign failed on both agents");
        return SshAgentMessage.Failure();
    }

    private async Task<byte[]?> TrySignAsync(byte[] keyBlob, byte[] data, uint flags, CancellationToken ct)
    {
        using var client = await ConnectToBackendAsync(ct);
        if (client == null)
            return null;

        try
        {
            return await client.SignAsync(keyBlob, data, flags, ct);
        }
        catch
        {
            return null;
        }
    }

    private async Task<SshAgentMessage> ForwardRequestAsync(SshAgentMessage request, CancellationToken ct)
    {
        Log($"Request: Forward {request.Type}");

        using var client = await ConnectToBackendAsync(ct);
        if (client == null)
            return SshAgentMessage.Failure();

        try
        {
            var response = await client.SendAsync(request, ct);
            return response ?? SshAgentMessage.Failure();
        }
        catch (Exception ex)
        {
            Log($"  Error: {ex.Message}");
            return SshAgentMessage.Failure();
        }
    }

    private async Task KillProcessAsync(string processName)
    {
        var processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            Log($"  {processName} is not running");
            return;
        }

        Log($"  Stopping {processName} ({processes.Length} processes)...");
        try
        {
            // WMICを使用（セッション跨ぎに強い）
            var psi = new ProcessStartInfo
            {
                FileName = "wmic",
                Arguments = $"process where name='{processName}.exe' delete",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            var proc = Process.Start(psi);
            if (proc != null)
            {
                await proc.WaitForExitAsync();
                var output = await proc.StandardOutput.ReadToEndAsync();
                if (!string.IsNullOrEmpty(output) && output.Contains("error", StringComparison.OrdinalIgnoreCase))
                    Log($"    wmic: {output.Trim()}");
            }

            // プロセスが完全に終了するまで待機
            for (int i = 0; i < 10; i++)
            {
                await Task.Delay(500);
                var remaining = Process.GetProcessesByName(processName);
                if (remaining.Length == 0)
                {
                    Log($"    Stopped");
                    return;
                }
            }
            Log($"    Warning: Some processes may still be running");
        }
        catch (Exception ex)
        {
            Log($"    Warning: {ex.Message}");
        }
    }

    private void StartProcessIfNeeded(string processName, string exePath)
    {
        // 既に起動していればスキップ
        var existing = Process.GetProcessesByName(processName);
        if (existing.Length > 0)
        {
            Log($"  {processName} is already running");
            return;
        }

        if (!File.Exists(exePath))
        {
            Log($"  Warning: {exePath} not found");
            return;
        }

        try
        {
            Log($"  Starting {processName}...");
            Process.Start(new ProcessStartInfo
            {
                FileName = exePath,
                UseShellExecute = true,
                WindowStyle = ProcessWindowStyle.Minimized
            });
        }
        catch (Exception ex)
        {
            Log($"  Error: {ex.Message}");
        }
    }

    private void Log(string message) => OnLog?.Invoke($"[{DateTime.Now:HH:mm:ss}] {message}");

    public async ValueTask DisposeAsync()
    {
        await _server.StopAsync();
    }
}
