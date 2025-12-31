using System.Text.Json;
using System.Text.Json.Serialization;

namespace SshAgentProxy;

public class Config
{
    [JsonPropertyName("proxyPipeName")]
    public string ProxyPipeName { get; set; } = "ssh-agent-proxy";

    [JsonPropertyName("backendPipeName")]
    public string BackendPipeName { get; set; } = "openssh-ssh-agent";

    [JsonPropertyName("agents")]
    public AgentsConfig Agents { get; set; } = new();

    [JsonPropertyName("keyMappings")]
    public List<KeyMapping> KeyMappings { get; set; } = [];

    [JsonPropertyName("defaultAgent")]
    public string DefaultAgent { get; set; } = "1Password";

    public static Config LoadOrCreate(string path)
    {
        if (File.Exists(path))
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<Config>(json) ?? new Config();
        }

        var defaultConfig = new Config();
        var options = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(defaultConfig, options));

        return defaultConfig;
    }

    public void Save(string path)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(path, JsonSerializer.Serialize(this, options));
    }
}

public class AgentsConfig
{
    [JsonPropertyName("onePassword")]
    public AgentAppConfig OnePassword { get; set; } = new()
    {
        Name = "1Password",
        ProcessName = "1Password",
        ExePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"1Password\app\8\1Password.exe")
    };

    [JsonPropertyName("bitwarden")]
    public AgentAppConfig Bitwarden { get; set; } = new()
    {
        Name = "Bitwarden",
        ProcessName = "Bitwarden",
        ExePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Programs\Bitwarden\Bitwarden.exe")
    };
}

public class AgentAppConfig
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("processName")]
    public string ProcessName { get; set; } = "";

    [JsonPropertyName("exePath")]
    public string ExePath { get; set; } = "";
}

public class KeyMapping
{
    [JsonPropertyName("comment")]
    public string? Comment { get; set; }

    [JsonPropertyName("fingerprint")]
    public string? Fingerprint { get; set; }

    [JsonPropertyName("agent")]
    public string Agent { get; set; } = "1Password";
}
