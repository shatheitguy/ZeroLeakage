using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace ZeroLeakage.UI.Services;

/// <summary>A file ZeroLeakage moved out of harm's way after ClamAV flagged it.</summary>
public sealed class VaultItem
{
    public Guid Id { get; init; }
    public string OriginalPath { get; init; } = "";
    public string ThreatName { get; init; } = "";
    public string Engine { get; init; } = "ClamAV";
    public string Sha256 { get; init; } = "";
    public long SizeBytes { get; init; }
    public DateTime QuarantinedAt { get; init; }
    /// <summary>False when the file couldn't be moved (locked, access denied); it is still listed so you can act.</summary>
    public bool Quarantined { get; init; } = true;
    public string? Error { get; init; }

    public string FileName => Path.GetFileName(OriginalPath);
    public string DateText => QuarantinedAt.ToString("dd MMM yyyy · HH:mm");
    public string SizeText => SizeBytes >= 1_048_576 ? $"{SizeBytes / 1_048_576d:0.0} MB" : $"{SizeBytes / 1024d:0} KB";
    public string StatusText => Quarantined ? "Quarantined by ZeroLeakage" : $"Detected · not moved ({Error})";
    public string ShortHash => Sha256.Length > 20 ? $"{Sha256[..12]}…{Sha256[^8..]}" : Sha256;
}

/// <summary>
/// ZeroLeakage's own quarantine for ClamAV detections: %LocalAppData%\ZeroLeakage\quarantine.
/// Files are stored XOR-scrambled with a random per-file key, so they can't run, can't be opened by
/// accident and aren't re-detected by other scanners. Restore puts the exact bytes back.
/// </summary>
public static class QuarantineVault
{
    public static string Folder { get; } = Path.Combine(UiSettingsStore.Directory, "quarantine");
    private static string IndexFile => Path.Combine(Folder, "index.json");
    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static IReadOnlyList<VaultItem> Items()
    {
        lock (Gate) return Load().OrderByDescending(i => i.QuarantinedAt).ToList();
    }

    private static List<VaultItem> Load()
    {
        try { return File.Exists(IndexFile) ? JsonSerializer.Deserialize<List<VaultItem>>(File.ReadAllText(IndexFile)) ?? new() : new(); }
        catch { return new(); }
    }

    private static void Save(List<VaultItem> items)
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllText(IndexFile, JsonSerializer.Serialize(items, Json));
    }

    private static string BlobPath(Guid id) => Path.Combine(Folder, id.ToString("N") + ".zlq");
    private static string KeyPath(Guid id) => Path.Combine(Folder, id.ToString("N") + ".key");

    /// <summary>Moves a flagged file into the vault. Never throws: failures are recorded on the item.</summary>
    public static async Task<VaultItem> QuarantineAsync(string path, string threat, string engine = "ClamAV")
    {
        var id = Guid.NewGuid();
        long size = 0;
        string sha = "";
        try
        {
            var fi = new FileInfo(path);
            size = fi.Length;
            Directory.CreateDirectory(Folder);
            byte[] key = RandomNumberGenerator.GetBytes(32);
            using (var sha256 = SHA256.Create())
            await using (var src = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true))
            await using (var dst = new FileStream(BlobPath(id), FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var buf = new byte[81920];
                long offset = 0;
                int n;
                while ((n = await src.ReadAsync(buf)) > 0)
                {
                    sha256.TransformBlock(buf, 0, n, null, 0);
                    for (int i = 0; i < n; i++) buf[i] ^= key[(offset + i) % key.Length];
                    offset += n;
                    await dst.WriteAsync(buf.AsMemory(0, n));
                }
                sha256.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                sha = Convert.ToHexString(sha256.Hash!).ToLowerInvariant();
            }
            await File.WriteAllBytesAsync(KeyPath(id), key);
            File.Delete(path);   // only after the scrambled copy is safely written
            var item = new VaultItem { Id = id, OriginalPath = path, ThreatName = threat, Engine = engine, Sha256 = sha, SizeBytes = size, QuarantinedAt = DateTime.Now };
            lock (Gate) { var all = Load(); all.Add(item); Save(all); }
            return item;
        }
        catch (Exception ex)
        {
            try { if (File.Exists(BlobPath(id))) File.Delete(BlobPath(id)); } catch { }
            try { if (File.Exists(KeyPath(id))) File.Delete(KeyPath(id)); } catch { }
            var item = new VaultItem
            {
                Id = id, OriginalPath = path, ThreatName = threat, Engine = engine, Sha256 = sha, SizeBytes = size,
                QuarantinedAt = DateTime.Now, Quarantined = false,
                Error = ex is UnauthorizedAccessException ? "access denied" : ex is IOException ? "file is in use" : ex.Message,
            };
            lock (Gate) { var all = Load(); all.Add(item); Save(all); }
            return item;
        }
    }

    /// <summary>Puts the original bytes back where they were (or next to it if a new file took its place).</summary>
    public static async Task<string> RestoreAsync(VaultItem item)
    {
        if (!item.Quarantined) { Forget(item); return item.OriginalPath; }
        var key = await File.ReadAllBytesAsync(KeyPath(item.Id));
        var target = item.OriginalPath;
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        if (File.Exists(target))
            target = Path.Combine(Path.GetDirectoryName(target)!, Path.GetFileNameWithoutExtension(target) + " (restored)" + Path.GetExtension(target));
        await using (var src = File.OpenRead(BlobPath(item.Id)))
        await using (var dst = new FileStream(target, FileMode.CreateNew))
        {
            var buf = new byte[81920];
            long offset = 0;
            int n;
            while ((n = await src.ReadAsync(buf)) > 0)
            {
                for (int i = 0; i < n; i++) buf[i] ^= key[(offset + i) % key.Length];
                offset += n;
                await dst.WriteAsync(buf.AsMemory(0, n));
            }
        }
        DeleteBlob(item.Id);
        Forget(item);
        return target;
    }

    /// <summary>Permanently deletes the quarantined copy.</summary>
    public static void Delete(VaultItem item)
    {
        DeleteBlob(item.Id);
        Forget(item);
    }

    private static void DeleteBlob(Guid id)
    {
        try { File.Delete(BlobPath(id)); } catch { }
        try { File.Delete(KeyPath(id)); } catch { }
    }

    private static void Forget(VaultItem item)
    {
        lock (Gate)
        {
            var all = Load();
            all.RemoveAll(i => i.Id == item.Id);
            Save(all);
        }
    }
}
