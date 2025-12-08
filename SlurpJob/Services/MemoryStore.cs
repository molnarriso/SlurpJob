using System.Collections.Concurrent;
using SlurpJob.Models;

namespace SlurpJob.Services;

public class MemoryStore
{
    // Key: PayloadHash
    private readonly ConcurrentDictionary<string, AttackDossier> _dossiers = new();
    
    // Circular Buffer for Live Feed (Fixed size 100)
    private readonly ConcurrentQueue<LiveEvent> _liveFeed = new();
    private const int MaxLiveFeedSize = 100;

    // OOM Protection
    private const long MaxMemoryBytes = 900 * 1024 * 1024; // 900MB
    private readonly AttackDossier _overflowDossier;

    public MemoryStore()
    {
        _overflowDossier = new AttackDossier
        {
            PayloadHash = "OVERFLOW",
            Protocol = "MIXED",
            PayloadData = System.Text.Encoding.UTF8.GetBytes("MEMORY OVERFLOW - DROPPED PAYLOADS")
        };
    }

    public void AddEvent(LiveEvent evt, string payloadHash, byte[] fullPayload, string? sni)
    {
        // 1. Add to Live Feed
        _liveFeed.Enqueue(evt);
        while (_liveFeed.Count > MaxLiveFeedSize)
        {
            _liveFeed.TryDequeue(out _);
        }

        // 2. Add to Dossier
        AttackDossier dossier;
        
        if (_dossiers.TryGetValue(payloadHash, out var existing))
        {
            dossier = existing;
        }
        else
        {
            // Check Memory
            if (GC.GetTotalMemory(false) > MaxMemoryBytes)
            {
                dossier = _overflowDossier;
            }
            else
            {
                dossier = new AttackDossier
                {
                    PayloadHash = payloadHash,
                    Protocol = evt.Protocol,
                    PayloadData = fullPayload,
                    SniHostname = sni,
                    FirstSeen = DateTime.UtcNow
                };
                _dossiers.TryAdd(payloadHash, dossier);
            }
        }

        UpdateDossier(dossier, evt);
    }

    private void UpdateDossier(AttackDossier dossier, LiveEvent evt)
    {
        dossier.LastSeen = DateTime.UtcNow;
        
        // Find active engagement (last 10 mins)
        // Note: ConcurrentBag is not ordered, but for simplicity we'll just check if we have any recent one or create new.
        // In a real high-concurrency scenario, this locking might need optimization, but for now:
        
        lock (dossier)
        {
            var engagement = dossier.Engagements.FirstOrDefault(e => (DateTime.UtcNow - e.LastSeen).TotalMinutes < 10);
            
            if (engagement == null)
            {
                engagement = new Engagement
                {
                    StartTime = DateTime.UtcNow,
                    LastSeen = DateTime.UtcNow,
                    TotalCount = 0
                };
                dossier.Engagements.Add(engagement);
            }

            engagement.LastSeen = DateTime.UtcNow;
            engagement.TotalCount++;
            engagement.SourceMap.AddOrUpdate(evt.SourceCountry, 1, (k, v) => v + 1);
        }
    }

    public IEnumerable<LiveEvent> GetLiveFeed()
    {
        return _liveFeed.ToArray().Reverse();
    }
    
    public IEnumerable<AttackDossier> GetDossiers()
    {
        return _dossiers.Values;
    }
}
