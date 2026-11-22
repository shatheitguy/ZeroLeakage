using System;
using System.IO;
using System.Text.Json;
using ZeroLeakage.UI.Models;

namespace ZeroLeakage.UI.Services;

public sealed class UiSettings
{
    public bool WizardCompleted { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public bool StartWithWindows { get; set; }
    public bool AutoUpdateDefinitions { get; set; } = true;
    public int UpdateWindowMinutes { get; set; } = 15;
    public ProtectionMode Mode { get; set; } = ProtectionMode.Balanced;
}

public static class UiSettingsStore
{
    public static string Directory { get; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ZeroLeakage");

    private static string FilePath => Path.Combine(Directory, "ui-settings.json");
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static UiSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<UiSettings>(File.ReadAllText(FilePath), Options) ?? new UiSettings();
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
        return new UiSettings();
    }

    public static void Save(UiSettings settings)
    {
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(settings, Options));
        }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
    }
}
