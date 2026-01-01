using System.Windows.Forms;
using SshAgentProxy.Protocol;

namespace SshAgentProxy.UI;

public class KeySelectionDialog : Form
{
    private readonly ListBox _keyListBox;
    private readonly Button _okButton;
    private readonly Button _cancelButton;
    private readonly Label _timerLabel;
    private readonly System.Windows.Forms.Timer _countdownTimer;
    private int _remainingSeconds;
    private readonly List<SshIdentity> _keys;
    private readonly Dictionary<string, string> _keyToAgent;

    public List<SshIdentity>? SelectedKeys { get; private set; }
    public bool RescanRequested { get; private set; }

    public KeySelectionDialog(List<SshIdentity> keys, Dictionary<string, string> keyToAgent, int timeoutSeconds = 30)
    {
        _keys = keys;
        _keyToAgent = keyToAgent;
        _remainingSeconds = timeoutSeconds;

        Text = "Select SSH Key";
        Width = 560;
        Height = 420;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        Font = new System.Drawing.Font("Segoe UI", 10F);
        Padding = new Padding(16);

        var label = new Label
        {
            Text = "Choose the SSH key(s) for this connection:",
            Location = new System.Drawing.Point(16, 16),
            AutoSize = true,
            Font = new System.Drawing.Font("Segoe UI", 11F, System.Drawing.FontStyle.Bold)
        };
        Controls.Add(label);

        _keyListBox = new ListBox
        {
            Location = new System.Drawing.Point(16, 50),
            Width = 512,
            Height = 240,
            SelectionMode = SelectionMode.MultiExtended,
            Font = new System.Drawing.Font("Consolas", 11F),
            ItemHeight = 26
        };

        foreach (var key in keys)
        {
            var agent = keyToAgent.TryGetValue(key.Fingerprint, out var a) ? a : "Unknown";
            var shortFingerprint = key.Fingerprint.Length > 16
                ? key.Fingerprint[..16] + "..."
                : key.Fingerprint;
            _keyListBox.Items.Add($"{key.Comment}  ({agent})  {shortFingerprint}");
        }

        if (_keyListBox.Items.Count > 0)
            _keyListBox.SelectedIndex = 0;

        Controls.Add(_keyListBox);

        _timerLabel = new Label
        {
            Text = $"Auto-selecting in {_remainingSeconds} seconds...",
            Location = new System.Drawing.Point(16, 300),
            AutoSize = true,
            ForeColor = System.Drawing.Color.FromArgb(100, 100, 100),
            Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Italic)
        };
        Controls.Add(_timerLabel);

        var rescanButton = new Button
        {
            Text = "Rescan",
            Location = new System.Drawing.Point(16, 340),
            Width = 90,
            Height = 32,
            FlatStyle = FlatStyle.System
        };
        rescanButton.Click += OnRescanClick;
        Controls.Add(rescanButton);

        _okButton = new Button
        {
            Text = "Use Selected",
            Location = new System.Drawing.Point(330, 340),
            Width = 100,
            Height = 32,
            DialogResult = DialogResult.OK,
            FlatStyle = FlatStyle.System
        };
        _okButton.Click += OnOkClick;
        Controls.Add(_okButton);

        _cancelButton = new Button
        {
            Text = "Cancel",
            Location = new System.Drawing.Point(438, 340),
            Width = 90,
            Height = 32,
            DialogResult = DialogResult.Cancel,
            FlatStyle = FlatStyle.System
        };
        Controls.Add(_cancelButton);

        AcceptButton = _okButton;
        CancelButton = _cancelButton;

        _countdownTimer = new System.Windows.Forms.Timer
        {
            Interval = 1000
        };
        _countdownTimer.Tick += OnTimerTick;
        _countdownTimer.Start();

        // Handle key events
        _keyListBox.KeyDown += (s, e) =>
        {
            if (e.KeyCode == Keys.Enter)
            {
                OnOkClick(s, e);
                DialogResult = DialogResult.OK;
                Close();
            }
        };

        // Double-click to select
        _keyListBox.DoubleClick += (s, e) =>
        {
            OnOkClick(s, e);
            DialogResult = DialogResult.OK;
            Close();
        };
    }

    private void OnTimerTick(object? sender, EventArgs e)
    {
        _remainingSeconds--;
        _timerLabel.Text = $"Auto-selecting in {_remainingSeconds} seconds...";

        if (_remainingSeconds <= 0)
        {
            _countdownTimer.Stop();
            OnOkClick(sender, e);
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private void OnOkClick(object? sender, EventArgs e)
    {
        _countdownTimer.Stop();
        SelectedKeys = new List<SshIdentity>();

        foreach (int index in _keyListBox.SelectedIndices)
        {
            SelectedKeys.Add(_keys[index]);
        }

        // If nothing selected, use first item
        if (SelectedKeys.Count == 0 && _keys.Count > 0)
        {
            SelectedKeys.Add(_keys[0]);
        }
    }

    private void OnRescanClick(object? sender, EventArgs e)
    {
        _countdownTimer.Stop();
        RescanRequested = true;
        DialogResult = DialogResult.Retry;
        Close();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _countdownTimer.Stop();
        base.OnFormClosing(e);
    }

    /// <summary>
    /// Show the dialog and return selected keys (thread-safe, works from non-UI thread)
    /// </summary>
    /// <param name="keys">Available keys to choose from</param>
    /// <param name="keyToAgent">Mapping of fingerprint to agent name</param>
    /// <param name="timeoutSeconds">Auto-select timeout</param>
    /// <param name="rescanRequested">True if user clicked Rescan button</param>
    /// <returns>Selected keys, or null if cancelled</returns>
    public static List<SshIdentity>? ShowDialog(
        List<SshIdentity> keys,
        Dictionary<string, string> keyToAgent,
        int timeoutSeconds,
        out bool rescanRequested)
    {
        List<SshIdentity>? result = null;
        bool rescan = false;

        // Must run on STA thread for Windows Forms
        var thread = new Thread(() =>
        {
            Application.EnableVisualStyles();
            using var dialog = new KeySelectionDialog(keys, keyToAgent, timeoutSeconds);
            var dialogResult = dialog.ShowDialog();
            if (dialogResult == DialogResult.OK)
            {
                result = dialog.SelectedKeys;
            }
            else if (dialogResult == DialogResult.Retry)
            {
                rescan = dialog.RescanRequested;
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        rescanRequested = rescan;
        return result;
    }

    /// <summary>
    /// Show the dialog and return selected keys (thread-safe, works from non-UI thread)
    /// </summary>
    public static List<SshIdentity>? ShowDialog(
        List<SshIdentity> keys,
        Dictionary<string, string> keyToAgent,
        int timeoutSeconds = 30)
    {
        return ShowDialog(keys, keyToAgent, timeoutSeconds, out _);
    }
}
