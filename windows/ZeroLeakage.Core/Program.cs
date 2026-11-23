using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeroLeakage.Core.Dns;
using ZeroLeakage.Core.Guard;
using ZeroLeakage.Core.Ipc;
using ZeroLeakage.Shared.Ipc;

// ZeroLeakage Core: the Windows service (LocalSystem) behind the desktop app's Guard page.
//   ZeroLeakage.Core.exe              run as the "ZeroLeakageCore" service (installed by the MSI)
//   ZeroLeakage.Core.exe --cleanup    remove every "ZeroLeakage Guard" firewall rule, restore DNS, delete Guard data (MSI uninstall)
//   ZeroLeakage.Core.exe --fw-status  read-only check of the Windows Firewall COM API (diagnostics)

if (args.Any(a => a.Equals("--cleanup", StringComparison.OrdinalIgnoreCase))) return CoreCli.Cleanup();
if (args.Any(a => a.Equals("--fw-status", StringComparison.OrdinalIgnoreCase))) return CoreCli.FirewallStatus();

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});
builder.Services.AddWindowsService(o => o.ServiceName = CoreIpc.ServiceName);
builder.Logging.AddFilter("Microsoft", LogLevel.Warning);

builder.Services.AddSingleton(GuardPaths.Default);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IFirewall, WindowsFirewall>();
builder.Services.AddSingleton<IFeedSource, HttpFeedSource>();
builder.Services.AddSingleton<ILocalNetworkInfo, LocalNetworkInfo>();
builder.Services.AddSingleton<IDnsConfigurator, WindowsDnsConfigurator>();
builder.Services.AddSingleton(sp => new GuardEngine(
    sp.GetRequiredService<GuardPaths>(), sp.GetRequiredService<IFirewall>(), sp.GetRequiredService<IFeedSource>(),
    sp.GetRequiredService<ILocalNetworkInfo>(), sp.GetRequiredService<IDnsConfigurator>(), sp.GetRequiredService<TimeProvider>(),
    sp.GetRequiredService<ILogger<GuardEngine>>()));
builder.Services.AddSingleton<IpcHandler>();
builder.Services.AddHostedService<GuardWorker>();
builder.Services.AddHostedService<PipeServer>();
builder.Services.AddHostedService<SecurityLogWatcher>();
builder.Services.AddHostedService<FirewallLogWatcher>();

// Initialize before the pipe opens, so the first status request already sees loaded state.
var host = builder.Build();
host.Services.GetRequiredService<GuardEngine>().Initialize();
host.Run();
return 0;

internal static class CoreCli
{
    /// <summary>MSI uninstall (deferred, as SYSTEM): firewall rules out, DNS back, Guard's ProgramData folder gone.</summary>
    public static int Cleanup()
    {
        int code = 0;
        try
        {
            int removed = new GuardFirewallSync(new WindowsFirewall()).Cleanup();
            Console.WriteLine($"Removed {removed} ZeroLeakage Guard firewall rule(s).");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Firewall cleanup failed: " + ex.Message);
            code = 1;
        }
        try
        {
            var paths = GuardPaths.Default;
            var dns = new DnsModeManager(new WindowsDnsConfigurator(), paths.DnsBackupFile, TimeProvider.System);
            if (dns.IsEnabled)
            {
                var (ok, error) = dns.Disable();
                Console.WriteLine(ok ? "Windows DNS restored." : "DNS restore failed: " + error);
                if (!ok) code = 1;
            }
            if (Directory.Exists(paths.Root) && code == 0) Directory.Delete(paths.Root, recursive: true);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Data cleanup failed: " + ex.Message);
            code = 1;
        }
        return code;
    }

    /// <summary>Read-only: proves the COM API is reachable and counts rules. Never changes anything.</summary>
    public static int FirewallStatus()
    {
        try
        {
            var fw = new WindowsFirewall();
            Console.WriteLine($"rules={fw.CountAllRules()} guardRules={fw.GetRules(GuardFirewallSync.Group).Count} " +
                              $"enabledForCurrentProfiles={fw.IsEnabledForCurrentProfiles()?.ToString() ?? "unknown"}");
            var (path, dropped) = FirewallLogWatcher.Locate();
            Console.WriteLine($"firewallLog={path} droppedPacketLogging={dropped} exists={File.Exists(path)}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }
}
