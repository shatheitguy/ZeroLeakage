using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeroLeakage.Shared.Ipc;

namespace ZeroLeakage.Core.Ipc;

/// <summary>
/// The \\.\pipe\ZeroLeakage.Core endpoint. ACL: SYSTEM full control; Administrators and the interactive user read/write
/// (they can't create pipe instances, so nobody can impersonate the server). The first instance uses
/// FILE_FLAG_FIRST_PIPE_INSTANCE so a squatter that grabbed the name first is detected instead of trusted.
/// </summary>
public sealed class PipeServer : BackgroundService
{
    private const int MaxConcurrent = 16;
    private readonly IpcHandler _handler;
    private readonly ILogger _log;
    private readonly string _pipeName;
    private readonly SemaphoreSlim _slots = new(MaxConcurrent, MaxConcurrent);

    public PipeServer(IpcHandler handler, ILogger<PipeServer> log) : this(handler, log, CoreIpc.PipeName) { }

    public PipeServer(IpcHandler handler, ILogger log, string pipeName)
    {
        _handler = handler;
        _log = log;
        _pipeName = pipeName;
    }

    public static PipeSecurity CreateSecurity()
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl, AccessControlType.Allow));
        var rw = PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize;
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), rw, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), rw, AccessControlType.Allow));
        // The process identity that owns the server (SYSTEM in production) must be able to add instances.
        using var me = WindowsIdentity.GetCurrent();
        if (me.User is { } self && !self.IsWellKnown(WellKnownSidType.LocalSystemSid))
            sec.AddAccessRule(new PipeAccessRule(self, PipeAccessRights.FullControl, AccessControlType.Allow));
        return sec;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        bool first = true;
        while (!ct.IsCancellationRequested)
        {
            await _slots.WaitAsync(ct).ConfigureAwait(false);
            NamedPipeServerStream server;
            try
            {
                server = NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
                    0, 0, CreateSecurity());
                first = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _slots.Release();
                _log.LogError(ex, "Couldn't create the {Pipe} pipe{Hint}", _pipeName, first ? " (another process may already own the name)" : "");
                try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
                continue;
            }

            try { await server.WaitForConnectionAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException)
            {
                await server.DisposeAsync().ConfigureAwait(false);
                _slots.Release();
                break;
            }
            catch (IOException ex)
            {
                _log.LogWarning(ex, "Pipe connection failed");
                await server.DisposeAsync().ConfigureAwait(false);
                _slots.Release();
                continue;
            }
            _ = Task.Run(() => ServeAsync(server, ct), CancellationToken.None);
        }
    }

    private async Task ServeAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            var reader = new PipeMessageReader(server);
            while (server.IsConnected && !ct.IsCancellationRequested)
            {
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
                idle.CancelAfter(TimeSpan.FromSeconds(60));
                var message = await reader.ReadAsync(idle.Token).ConfigureAwait(false);
                if (message is null) break;
                var response = await _handler.HandleJsonAsync(message, ct).ConfigureAwait(false);
                await PipeMessageWriter.WriteAsync(server, response, ct).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidDataException or ObjectDisposedException)
        {
            // client went away, idle, or sent junk: just drop the connection
        }
        finally
        {
            await server.DisposeAsync().ConfigureAwait(false);
            _slots.Release();
        }
    }
}
