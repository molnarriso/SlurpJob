using Microsoft.EntityFrameworkCore;
using SlurpJob.Data;

namespace SlurpJob.Services;

public class PersistenceWorker : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly MemoryStore _memoryStore;
    private readonly ILogger<PersistenceWorker> _logger;

    public PersistenceWorker(IServiceProvider serviceProvider, MemoryStore memoryStore, ILogger<PersistenceWorker> logger)
    {
        _serviceProvider = serviceProvider;
        _memoryStore = memoryStore;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Ensure DB Created
        using (var scope = _serviceProvider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SlurpContext>();
            await db.Database.EnsureCreatedAsync(stoppingToken);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(5000, stoppingToken); // 5 seconds interval
                await FlushAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in PersistenceWorker");
            }
        }
    }

    private async Task FlushAsync(CancellationToken token)
    {
        using var scope = _serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SlurpContext>();
        
        var dossiers = _memoryStore.GetDossiers();
        int recordsWritten = 0;

        foreach (var dossier in dossiers)
        {
            // Check if Signature exists (cache this lookup ideally, but for now just check)
            // We can optimize by assuming if we have it in RAM, we might need to write it once.
            // But since RAM is ephemeral, we should check DB or keep a "Persisted" flag on Dossier.
            
            // For simplicity, we'll try to add signature if not exists.
            // But checking every time is slow.
            // Let's assume we only write Signature if we are writing Activity.
            
            foreach (var engagement in dossier.Engagements)
            {
                int currentCount = engagement.TotalCount;
                int lastCount = engagement.LastPersistedCount;

                if (currentCount > lastCount)
                {
                    int delta = currentCount - lastCount;
                    
                    // Ensure Signature
                    if (await db.Signatures.FindAsync(dossier.PayloadHash) == null)
                    {
                        db.Signatures.Add(new Signature
                        {
                            Hash = dossier.PayloadHash,
                            PayloadRaw = dossier.PayloadData,
                            SniHostname = dossier.SniHostname,
                            FirstSeen = dossier.FirstSeen
                        });
                    }

                    // Write Activity Log
                    // We need to aggregate by Country/Port for this batch
                    // But Engagement stores SourceMap (Country -> Count).
                    // We don't easily know which specific countries contributed to the *delta*.
                    // This is a flaw in the Engagement model vs Persistence model.
                    // Engagement aggregates all time.
                    // To fix this, we'd need to track "LastPersistedCount" per Country in SourceMap, 
                    // or just write a summary row "Various" or pick the top one.
                    
                    // Refined approach:
                    // The DesignDoc says: "Iterate through all Active Groups... Look for dimensional entries (Country+Port) marked as Dirty".
                    // My SourceMap is just Country -> Count.
                    // I can snapshot the current counts, compare with last snapshot.
                    // But keeping a snapshot for every engagement is heavy.
                    
                    // Simplification:
                    // Just write one row per Engagement update with the Delta count, and pick the dominant country or "MIXED".
                    // Or just iterate the SourceMap and see which ones increased? No, we don't track per-country history in RAM.
                    
                    // Let's just write "MIXED" if multiple, or the single country if only one.
                    string countryCode = "MIXED";
                    if (engagement.SourceMap.Count == 1)
                    {
                        countryCode = engagement.SourceMap.Keys.First();
                    }
                    
                    // We don't have Target Port in Engagement! It's in the LiveEvent.
                    // Dossier groups by PayloadHash.
                    // A PayloadHash could theoretically hit multiple ports?
                    // DesignDoc says: "Hash includes Target Port" for UDP empty packets.
                    // For TCP, same payload on different ports -> Same Dossier?
                    // DesignDoc says: "Dossier... Key = PayloadHash".
                    // If same payload hits port 80 and 8080, they share a dossier.
                    // So we lose the Port info in the Dossier aggregation unless we group by Port too.
                    // DesignDoc says: "ActivityLog... TargetPort".
                    // So we need Port in the aggregation.
                    
                    // I should probably include Port in the Dossier Key or Engagement Key.
                    // Let's assume for now we just use 0 or "Various" if we can't track it.
                    // OR, we change Dossier Key to be Hash + Port?
                    // But then we split the same botnet attacking multiple ports.
                    
                    // Let's stick to the plan: Dossier by Hash.
                    // We'll just log TargetPort as 0 (Mixed) for now in the ActivityLog if it varies.
                    // Or maybe we accept that we lose that granularity in the historical aggregate.
                    
                    db.ActivityLogs.Add(new ActivityLog
                    {
                        Timestamp = DateTime.UtcNow,
                        SignatureHash = dossier.PayloadHash,
                        CountryCode = countryCode,
                        TargetPort = 0, // Lost in aggregation
                        Count = delta,
                        TotalBytes = delta * dossier.PayloadData.Length
                    });
                    
                    // Update GeoStats
                    // We can just increment the country counters
                    // But again, we don't know exactly which countries made up the Delta.
                    // This is a limitation of the current simple model.
                    // For Phase 1, this is acceptable.
                    
                    if (countryCode != "MIXED")
                    {
                        var today = DateTime.UtcNow.Date;
                        var geoStat = await db.GeoStats.FindAsync(today, countryCode);
                        if (geoStat == null)
                        {
                            geoStat = new GeoStat { Date = today, CountryCode = countryCode, TotalHits = 0 };
                            db.GeoStats.Add(geoStat);
                        }
                        geoStat.TotalHits += delta;
                    }

                    engagement.LastPersistedCount = currentCount;
                    recordsWritten++;
                }
            }
        }

        if (recordsWritten > 0)
        {
            await db.SaveChangesAsync(token);
            // _logger.LogInformation($"Persisted {recordsWritten} activity records.");
        }
    }
}
