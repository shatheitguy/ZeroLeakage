using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Input;
using ZeroLeakage.Shared.Link;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.ViewModels;

public sealed record PolicyChip(string Id, bool IsLocked)
{
    public bool CanRemove => !IsLocked;
}

/// <summary>
/// Account &amp; sync: link this PC to a ZeroLeakage Server (pairing code, or username + password — the password is never
/// stored, only the DPAPI-protected device token) and show who is signed in and what the server manages.
/// </summary>
public sealed class AccountViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly SyncService _sync;
    private bool _isOpen, _usePassword, _busy, _useServerDns;
    private string _serverAddress = "", _pairingCode = "", _username = "", _serviceInput = "";
    private string? _error, _notice;

    public AccountViewModel(MainViewModel shell, SyncService sync)
    {
        _shell = shell;
        _sync = sync;
        _sync.Changed += (_, _) => Ui.Post(Refresh);

        OpenCommand = new RelayCommand(() => { shell.IsProfileMenuOpen = false; IsOpen = true; Refresh(); });
        CloseCommand = new RelayCommand(() => { IsOpen = false; Password = ""; PasswordCleared?.Invoke(); });
        LinkCommand = new AsyncRelayCommand(LinkAsync, () => !IsLinked && !_busy && ServerAddress.Trim().Length > 0 &&
            (UsePassword ? Username.Trim().Length > 0 : PairingCode.Trim().Length > 0));
        SyncNowCommand = new AsyncRelayCommand(async () =>
        {
            var r = await _sync.SyncNowAsync();
            _shell.ShowSnackbar(r.Ok ? $"Synced with {_sync.State?.ServerName}" : "Sync failed: " + r.Error);
        }, () => IsLinked && !_busy);
        UnlinkCommand = new RelayCommand(() => _shell.RequestConfirm(
            "Unlink this PC?",
            $"ZeroLeakage stops following {ServerName}. Your own filter lists and rules from before linking come back, Guard stops using the server, and if this PC used the server as its DNS the previous DNS settings are restored. The device stays listed on the server until its admin removes it.",
            "Unlink", true, async () =>
            {
                await _sync.UnlinkAsync();
                _shell.ShowSnackbar("Unlinked · this PC uses its own protection again");
            }), () => IsLinked && !_busy);
        AddServiceCommand = new AsyncRelayCommand(async () =>
        {
            var err = await _sync.SetUserServiceAsync(ServiceInput, blocked: true);
            if (err is null) ServiceInput = "";
            else _shell.ShowSnackbar(err);
        }, () => IsLinked && ServiceInput.Trim().Length > 0);
        RemoveServiceCommand = new AsyncRelayCommand(async p =>
        {
            if (p is not PolicyChip c) return;
            var err = await _sync.SetUserServiceAsync(c.Id, blocked: false);
            _shell.ShowSnackbar(err ?? $"{c.Id} will be unblocked after the next sync");
        });
        Refresh();
    }

    public event Action? PasswordCleared;

    public bool IsOpen { get => _isOpen; set => SetProperty(ref _isOpen, value); }
    public ICommand OpenCommand { get; }
    public ICommand CloseCommand { get; }
    public ICommand LinkCommand { get; }
    public ICommand SyncNowCommand { get; }
    public ICommand UnlinkCommand { get; }
    public ICommand AddServiceCommand { get; }
    public ICommand RemoveServiceCommand { get; }

    // ───────────── link form ─────────────
    public bool UsePassword { get => _usePassword; set { if (SetProperty(ref _usePassword, value)) OnPropertyChanged(nameof(UsePairingCode)); } }
    public bool UsePairingCode { get => !_usePassword; set => UsePassword = !value; }

    public string ServerAddress
    {
        get => _serverAddress;
        set { if (SetProperty(ref _serverAddress, value ?? "")) OnPropertyChanged(nameof(AddressWarning)); }
    }

    public string? AddressWarning =>
        ZeroLeakage.Shared.Link.ServerAddress.TryNormalize(_serverAddress, out _, out _, out var warn) ? warn : null;

    public string PairingCode { get => _pairingCode; set => SetProperty(ref _pairingCode, value ?? ""); }
    public string Username { get => _username; set => SetProperty(ref _username, value ?? ""); }
    /// <summary>Set from the PasswordBox; sent once to the server, never stored.</summary>
    public string Password { private get; set; } = "";

    public string? Error { get => _error; private set => SetProperty(ref _error, value); }
    public string? Notice { get => _notice; private set => SetProperty(ref _notice, value); }
    public bool IsBusy { get => _busy; private set => SetProperty(ref _busy, value); }

    private async Task LinkAsync()
    {
        Error = Notice = null;
        IsBusy = true;
        try
        {
            var r = UsePassword
                ? await _sync.SignInAsync(ServerAddress, Username, Password)
                : await _sync.LinkWithCodeAsync(ServerAddress, PairingCode);
            Password = "";
            PasswordCleared?.Invoke();
            if (!r.Ok) { Error = r.Error; return; }
            PairingCode = "";
            Notice = r.Error ?? r.Warning;
            _shell.ShowSnackbar($"Linked to {_sync.State?.ServerName}");
        }
        finally
        {
            IsBusy = false;
            Refresh();
        }
    }

    // ───────────── status ─────────────
    public bool IsLinked => _sync.IsLinked;
    public bool IsNotLinked => !IsLinked;
    public string ServerName => _sync.State?.ServerName ?? "";
    public string ServerUrl => _sync.State?.ServerUrl ?? "";
    public string SignedInAs => _sync.State is { } s ? (s.Username is { Length: > 0 } u ? u : "Paired device") : "";
    public string DeviceName => _sync.State?.DeviceName ?? "";
    public string PolicyVersionText => _sync.State?.PolicyVersion is { } v ? "v" + v : "—";
    public string LastSyncText => _sync.IsSyncing ? "syncing…" : _sync.State?.LastSync is { } t ? Ago(t) : "never";
    public string? SyncError => _sync.State?.LastError;
    public bool IsRevoked => _sync.State?.Revoked ?? false;

    public string ProfileTitle => _sync.State is { } s ? (s.Username is { Length: > 0 } u ? u : s.DeviceName) : "Local profile";
    public string ProfileSubtitle => _sync.State is { } s
        ? $"{(s.Username is { Length: > 0 } ? s.DeviceName + " · " : "")}{s.ServerName}{(s.LastError is null ? "" : " · sync error")}"
        : "Not signed in · rules stay on this PC";
    public string MenuCaption => IsLinked ? $"Linked to {ServerName} · synced {LastSyncText}" : "Link to your ZeroLeakage Server (optional)";

    public bool UseServerDns
    {
        get => _useServerDns;
        set
        {
            if (!SetProperty(ref _useServerDns, value)) return;
            _ = SetDnsAsync(value);
        }
    }

    public bool CanUseServerDns => IsLinked && !string.IsNullOrWhiteSpace(_sync.State?.DohUrl);
    public string ServerDnsText => _sync.State?.DohUrl is { Length: > 0 } d
        ? $"Windows will resolve every name through {d} (DNS over HTTPS, no plain-DNS fallback). Turning this off or unlinking restores your previous DNS settings. Needs the ZeroLeakage Core service and Windows 11."
        : "Your server didn't give this device a DNS-over-HTTPS address.";

    private async Task SetDnsAsync(bool on)
    {
        var err = await _sync.SetUseServerDnsAsync(on);
        if (err is not null)
        {
            _shell.ShowSnackbar(err);
            _useServerDns = _sync.State?.UseServerDns ?? false;
            OnPropertyChanged(nameof(UseServerDns));
        }
        else _shell.ShowSnackbar(on ? "This PC now uses your server for DNS" : "Previous DNS settings restored");
    }

    // ───────────── server policy (read-only where the admin set it) ─────────────
    public ObservableCollection<PolicyChip> LockedLists { get; } = new();
    public ObservableCollection<PolicyChip> Services { get; } = new();
    public ObservableCollection<PolicyChip> Categories { get; } = new();
    public string SafeSearchText { get; private set; } = "—";
    public string BlockModeText { get; private set; } = "—";
    public string SchedulesText { get; private set; } = "—";
    public string GuardPolicyText { get; private set; } = "—";
    public bool BypassBlocking { get; private set; }
    public string ServiceInput { get => _serviceInput; set => SetProperty(ref _serviceInput, value ?? ""); }

    public void Refresh()
    {
        var st = _sync.State;
        var locks = _sync.Locks;
        LockedLists.Clear();
        Services.Clear();
        Categories.Clear();
        if (st is not null)
        {
            var names = App.Filters?.Lists.ToDictionary(l => l.Id, l => l.Name, StringComparer.OrdinalIgnoreCase);
            foreach (var id in locks.Lists.OrderBy(x => x)) LockedLists.Add(new PolicyChip(names is not null && names.TryGetValue(id, out var n) ? n : id, true));
            var user = st.PendingUserPolicy ?? st.UserPolicy ?? new UserPolicy();
            foreach (var s in locks.Services.Concat(user.Services).Concat(st.Policy?.Services ?? new()).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
                Services.Add(new PolicyChip(s, locks.IsServiceLocked(s) || !user.Services.Contains(s, StringComparer.OrdinalIgnoreCase)));
            foreach (var c in locks.Categories.Concat(user.Categories).Concat(st.Policy?.Categories ?? new()).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
                Categories.Add(new PolicyChip(c, locks.IsCategoryLocked(c) || !user.Categories.Contains(c, StringComparer.OrdinalIgnoreCase)));
            SafeSearchText = Describe(st.Locked?.SafeSearch ?? st.Policy?.SafeSearch);
            BlockModeText = Describe(st.Policy?.BlockMode);
            SchedulesText = st.Policy?.Schedules is { ValueKind: JsonValueKind.Array } a ? $"{a.GetArrayLength()} schedule(s)" : "none";
            GuardPolicyText = st.Policy?.Guard is { } g ? $"Guard {(g.Enabled ? "on" : "off")} · drop malicious IPs {(g.DropMaliciousIps ? "on" : "off")}" : "not set";
            BypassBlocking = st.Policy?.BypassBlocking ?? false;
            _useServerDns = st.UseServerDns;
        }
        else _useServerDns = false;

        foreach (var p in new[]
                 {
                     nameof(IsLinked), nameof(IsNotLinked), nameof(ServerName), nameof(ServerUrl), nameof(SignedInAs), nameof(DeviceName),
                     nameof(PolicyVersionText), nameof(LastSyncText), nameof(SyncError), nameof(IsRevoked), nameof(ProfileTitle), nameof(ProfileSubtitle),
                     nameof(MenuCaption), nameof(UseServerDns), nameof(CanUseServerDns), nameof(ServerDnsText), nameof(SafeSearchText),
                     nameof(BlockModeText), nameof(SchedulesText), nameof(GuardPolicyText), nameof(BypassBlocking),
                 })
            OnPropertyChanged(p);
        CommandManager.InvalidateRequerySuggested();
    }

    private static string Describe(JsonElement? e)
    {
        if (e is not { } v) return "not set";
        return v.ValueKind switch
        {
            JsonValueKind.True => "on",
            JsonValueKind.False => "off",
            JsonValueKind.String => v.GetString() ?? "",
            JsonValueKind.Object when v.TryGetProperty("enabled", out var en) && en.ValueKind is JsonValueKind.True or JsonValueKind.False =>
                en.GetBoolean()
                    ? "on" + (v.EnumerateObject().Where(p => p.Name != "enabled" && p.Value.ValueKind == JsonValueKind.True).Select(p => p.Name).ToList() is { Count: > 0 } l
                        ? " · " + string.Join(", ", l) : "")
                    : "off",
            JsonValueKind.Null or JsonValueKind.Undefined => "not set",
            _ => v.GetRawText().Length > 60 ? v.GetRawText()[..60] + "…" : v.GetRawText(),
        };
    }

    private static string Ago(DateTimeOffset t)
    {
        var d = DateTimeOffset.Now - t;
        if (d.TotalMinutes < 1) return "just now";
        if (d.TotalHours < 1) return $"{(int)d.TotalMinutes} min ago";
        if (d.TotalDays < 1) return $"{(int)d.TotalHours} h ago";
        return $"{(int)d.TotalDays} d ago";
    }
}
