using System.Net;

namespace ZeroLeakage.Core.Guard;

public sealed record DetectionHit(IPAddress Ip, int Events, DateTimeOffset First, DateTimeOffset Last);

/// <summary>
/// Local CrowdSec-style "leaky bucket": N failed logons from one source IP within a sliding window
/// (Windows Security event 4625 → RDP/SMB brute force). The bucket empties once it fires.
/// </summary>
public sealed class BruteForceDetector
{
    private const int MaxTrackedIps = 50_000;
    private readonly Dictionary<IPAddress, Queue<DateTimeOffset>> _events = new();

    public BruteForceDetector(int threshold, TimeSpan window)
    {
        Threshold = Math.Max(1, threshold);
        Window = window <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : window;
    }

    public int Threshold { get; }
    public TimeSpan Window { get; }
    public int TrackedIps => _events.Count;

    public DetectionHit? Record(IPAddress ip, DateTimeOffset at)
    {
        if (!_events.TryGetValue(ip, out var q))
        {
            if (_events.Count >= MaxTrackedIps) Prune(at);
            if (_events.Count >= MaxTrackedIps) return null;
            _events[ip] = q = new Queue<DateTimeOffset>();
        }
        q.Enqueue(at);
        while (q.Count > 0 && at - q.Peek() > Window) q.Dequeue();
        if (q.Count < Threshold) return null;
        var hit = new DetectionHit(ip, q.Count, q.Peek(), at);
        _events.Remove(ip);
        return hit;
    }

    public void Prune(DateTimeOffset now)
    {
        foreach (var (ip, q) in _events.ToList())
        {
            while (q.Count > 0 && now - q.Peek() > Window) q.Dequeue();
            if (q.Count == 0) _events.Remove(ip);
        }
    }
}

/// <summary>Port scan: one source hitting many distinct closed ports (dropped inbound packets in the firewall log).</summary>
public sealed class PortScanDetector
{
    private const int MaxTrackedIps = 50_000;
    private readonly Dictionary<IPAddress, List<(DateTimeOffset At, int Port)>> _events = new();

    public PortScanDetector(int distinctPorts, TimeSpan window)
    {
        DistinctPorts = Math.Max(2, distinctPorts);
        Window = window <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : window;
    }

    public int DistinctPorts { get; }
    public TimeSpan Window { get; }

    public DetectionHit? Record(IPAddress ip, int port, DateTimeOffset at)
    {
        if (!_events.TryGetValue(ip, out var list))
        {
            if (_events.Count >= MaxTrackedIps) Prune(at);
            if (_events.Count >= MaxTrackedIps) return null;
            _events[ip] = list = new List<(DateTimeOffset, int)>();
        }
        list.Add((at, port));
        list.RemoveAll(e => at - e.At > Window);
        int distinct = list.Select(e => e.Port).Distinct().Count();
        if (distinct < DistinctPorts) return null;
        var hit = new DetectionHit(ip, distinct, list[0].At, at);
        _events.Remove(ip);
        return hit;
    }

    public void Prune(DateTimeOffset now)
    {
        foreach (var (ip, list) in _events.ToList())
        {
            list.RemoveAll(e => now - e.At > Window);
            if (list.Count == 0) _events.Remove(ip);
        }
    }
}
