using System;
using System.IO;
using Microsoft.Win32;

namespace ZeroLeakage.UI.Services;

/// <summary>
/// "Start with Windows": a per-user Run entry that launches ZeroLeakage hidden in the tray (--tray) at sign-in.
/// On by default for installed copies; the Settings switch turns it off.
/// </summary>
public static class AutoStart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "ZeroLeakage";

    /// <summary>True when running from Program Files (an MSI install), not from a dev build folder.</summary>
    public static bool IsInstalledCopy
    {
        get
        {
            var exe = Environment.ProcessPath;
            if (exe is null) return false;
            foreach (var root in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
            {
                var dir = Environment.GetFolderPath(root);
                if (dir.Length > 0 && exe.StartsWith(dir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    public static void Apply(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
        var exe = Environment.ProcessPath;
        if (enabled && exe is not null) key.SetValue(ValueName, $"\"{exe}\" --tray");
        else key.DeleteValue(ValueName, throwOnMissingValue: false);
    }

    /// <summary>
    /// Called on every launch: turns auto-start on once by default, then keeps the Run entry pointing at the
    /// current install (so it survives upgrades and moves). Dev builds never register themselves.
    /// </summary>
    public static void EnsureOnLaunch(UiSettings settings)
    {
        if (!IsInstalledCopy) return;
        if (!settings.AutoStartDefaulted)
        {
            settings.StartWithWindows = true;
            settings.AutoStartDefaulted = true;
            UiSettingsStore.Save(settings);
        }
        try { Apply(settings.StartWithWindows); }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
    }
}
