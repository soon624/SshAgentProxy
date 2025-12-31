using SshAgentProxy;

// コマンドライン引数でテスト
if (args.Length > 0 && args[0] == "--test-switch")
{
    var targetAgent = args.Length > 1 ? args[1] : "1Password";
    var force = args.Contains("--force");
    await TestSwitchAsync(targetAgent, force);
    return;
}

Console.WriteLine("╔══════════════════════════════════════╗");
Console.WriteLine("║     SSH Agent Proxy                  ║");
Console.WriteLine("║     1Password / Bitwarden Switcher   ║");
Console.WriteLine("╚══════════════════════════════════════╝");
Console.WriteLine();

var configPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
    "SshAgentProxy",
    "config.json");

Directory.CreateDirectory(Path.GetDirectoryName(configPath)!);
Console.WriteLine($"Config: {configPath}");
Console.WriteLine();

var config = Config.LoadOrCreate(configPath);

await using var proxy = new SshAgentProxyService(config);
proxy.OnLog += Console.WriteLine;

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

await proxy.StartAsync(cts.Token);

Console.WriteLine();
Console.WriteLine("Commands: '1' = switch to 1Password, '2' = switch to Bitwarden, 'q' = quit");
Console.WriteLine("Press Ctrl+C to stop");
Console.WriteLine();

// コンソールが使えるかチェック
bool consoleAvailable = true;
try
{
    _ = Console.KeyAvailable;
}
catch
{
    consoleAvailable = false;
    Console.WriteLine("(Running without interactive console)");
}

try
{
    if (consoleAvailable)
    {
        while (!cts.Token.IsCancellationRequested)
        {
            if (Console.KeyAvailable)
            {
                var key = Console.ReadKey(intercept: true);
                switch (key.KeyChar)
                {
                    case '1':
                        await proxy.SwitchToAsync("1Password", cts.Token);
                        break;
                    case '2':
                        await proxy.SwitchToAsync("Bitwarden", cts.Token);
                        break;
                    case 'q':
                    case 'Q':
                        cts.Cancel();
                        break;
                }
            }
            await Task.Delay(100, cts.Token);
        }
    }
    else
    {
        // コンソールなしの場合は無限待機
        await Task.Delay(Timeout.Infinite, cts.Token);
    }
}
catch (OperationCanceledException)
{
    // 正常終了
}

Console.WriteLine();
Console.WriteLine("Shutting down...");

// テスト用関数
async Task TestSwitchAsync(string targetAgent, bool force)
{
    Console.WriteLine($"=== Testing switch to {targetAgent} (force={force}) ===");
    Console.WriteLine();

    var testConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SshAgentProxy",
        "config.json");
    var testConfig = Config.LoadOrCreate(testConfigPath);

    await using var testProxy = new SshAgentProxyService(testConfig);
    testProxy.OnLog += Console.WriteLine;

    Console.WriteLine("Attempting switch...");
    Console.WriteLine();

    if (force)
    {
        await testProxy.ForceSwitchToAsync(targetAgent, CancellationToken.None);
    }
    else
    {
        await testProxy.SwitchToAsync(targetAgent, CancellationToken.None);
    }

    Console.WriteLine();
    Console.WriteLine("=== Switch complete ===");
}
