using System.Collections.Concurrent;
using System.Net;

namespace SlurpJob.Models;

public class AttackDossier
{
    public string PayloadHash { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty; // TCP/UDP
    public byte[] PayloadData { get; set; } = Array.Empty<byte>();
    public string? SniHostname { get; set; }
    
    // Thread-safe list of engagements
    public ConcurrentBag<Engagement> Engagements { get; set; } = new();
    
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
}

public class Engagement
{
    public DateTime StartTime { get; set; }
    public DateTime LastSeen { get; set; }
    public int TotalCount { get; set; }
    public int LastPersistedCount { get; set; }
    
    // Country Code -> Count
    public ConcurrentDictionary<string, int> SourceMap { get; set; } = new();
}

public class LiveEvent
{
    public DateTime Timestamp { get; set; }
    public string SourceCountry { get; set; } = "XX";
    public IPAddress SourceIp { get; set; } = IPAddress.None;
    public int TargetPort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public byte[] PayloadSnippet { get; set; } = Array.Empty<byte>();
    public string PayloadHash { get; set; } = string.Empty;
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
}

public class TimelineBucket
{
    public DateTime Timestamp { get; set; }
    public int TcpCount { get; set; }
    public int UdpCount { get; set; }
    public int TotalCount => TcpCount + UdpCount;
}
