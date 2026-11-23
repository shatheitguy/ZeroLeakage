using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using ZeroLeakage.Shared.Ipc;
using ZeroLeakage.Shared.Link;
using ZeroLeakage.UI.Services.Dns;

namespace ZeroLeakage.UI.Services;

public enum CoreServiceState { Unknown, NotInstalled, Stopped, Starting, Stopping, Running, Paused }

/// <summary>
/// The desktop app's view of the ZeroLeakage Core Windows service: is it installed / running (read-only SCM query),
/// and requests over the \\.\pipe\ZeroLeakage.Core named pipe. Never throws for "service not there".
/// </summary>
public static class CoreServiceClient
{
    public static CoreServiceState QueryState()
    {
        IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
        try
        {
            scm = OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
            if (scm == IntPtr.Zero) return CoreServiceState.Unknown;
            svc = OpenServiceW(scm, CoreIpc.ServiceName, SERVICE_QUERY_STATUS);
            if (svc == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST ? CoreServiceState.NotInstalled : CoreServiceState.Unknown;
            if (!QueryServiceStatus(svc, out var st)) return CoreServiceState.Unknown;
            return st.dwCurrentState switch
            {
                1 => CoreServiceState.Stopped,
                2 => CoreServiceState.Starting,
                3 => CoreServiceState.Stopping,
                4 => CoreServiceState.Running,
                5 or 6 or 7 => CoreServiceState.Paused,
                _ => CoreServiceState.Unknown,
            };
        }
        finally
        {
            if (svc != IntPtr.Zero) CloseServiceHandle(svc);
            if (scm != IntPtr.Zero) CloseServiceHandle(scm);
        }
    }

    public static bool IsRunning() => QueryState() == CoreServiceState.Running;

    /// <summary>Sends a request; null when the service isn't running or didn't answer.</summary>
    public static async Task<CoreResponse?> TrySendAsync(CoreRequest request, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        if (!IsRunning()) return null;
        try { return await CorePipeClient.SendAsync(request, timeout ?? TimeSpan.FromSeconds(4), ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or UnauthorizedAccessException
                                       or System.Text.Json.JsonException or InvalidDataException)
        {
            return null;
        }
    }

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr service, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);
}

/// <summary>Sync's view of the DNS filter state; every call is marshalled to the UI thread.</summary>
public sealed class FilterSyncTarget : ISyncTarget
{
    private readonly FilterListService _filters;

    public FilterSyncTarget(FilterListService filters) => _filters = filters;

    public System.Collections.Generic.IReadOnlyCollection<string> CatalogListIds =>
        OnUi(() => System.Linq.Enumerable.ToList(System.Linq.Enumerable.Select(System.Linq.Enumerable.Where(_filters.Lists, l => !l.IsCustom), l => l.Id)));

    public Task<LocalProtectionSnapshot> SnapshotAsync() => Task.FromResult(OnUi(_filters.Snapshot));

    public Task ApplyAsync(SyncPlan plan, CancellationToken ct) => OnUiAsync(() => _filters.ApplyManagedAsync(plan));

    public Task RestoreAsync(LocalProtectionSnapshot snapshot, CancellationToken ct) => OnUiAsync(() => _filters.RestoreLocalAsync(snapshot));

    private static T OnUi<T>(Func<T> f)
    {
        var d = Application.Current?.Dispatcher;
        return d is null || d.CheckAccess() ? f() : d.Invoke(f);
    }

    private static Task OnUiAsync(Func<Task> f)
    {
        var d = Application.Current?.Dispatcher;
        return d is null || d.CheckAccess() ? f() : d.InvokeAsync(f).Task.Unwrap();
    }
}
