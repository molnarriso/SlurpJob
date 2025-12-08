using Microsoft.EntityFrameworkCore;
using SlurpJob.Data;
using SlurpJob.Models;

namespace SlurpJob.Services;

public class HistoryLoader : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly MemoryStore _memoryStore;
    private readonly ILogger<HistoryLoader> _logger;

    public HistoryLoader(IServiceProvider serviceProvider, MemoryStore memoryStore, ILogger<HistoryLoader> logger)
    {
        _serviceProvider = serviceProvider;
        _memoryStore = memoryStore;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SlurpContext>();
            
            // Ensure DB is created first (PersistenceWorker does this too, but we might race)
            await db.Database.EnsureCreatedAsync(cancellationToken);

            // Get last 50 activity logs
            var logs = await db.ActivityLogs
                .OrderByDescending(a => a.Timestamp)
                .Take(50)
                .ToListAsync(cancellationToken);

            _logger.LogInformation($"HistoryLoader: Found {logs.Count} activity logs.");

            if (logs.Any())
            {
                var history = new List<LiveEvent>();
                
                // Get signatures for these logs
                var hashes = logs.Select(l => l.SignatureHash).Distinct().ToList();
                var signatures = await db.Signatures
                    .Where(s => hashes.Contains(s.Hash))
                    .ToDictionaryAsync(s => s.Hash, s => s, cancellationToken);
                
                _logger.LogInformation($"HistoryLoader: Found {signatures.Count} matching signatures.");

                foreach (var log in logs.OrderBy(l => l.Timestamp)) // Re-order to chronological for insertion
                {
                    if (signatures.TryGetValue(log.SignatureHash, out var sig))
                    {
                        var evt = new LiveEvent
                        {
                            Timestamp = log.Timestamp,
                            SourceCountry = log.CountryCode,
                            SourceIp = System.Net.IPAddress.Parse("127.0.0.1"), // Placeholder
                            TargetPort = log.TargetPort == 0 ? 80 : log.TargetPort, // Default to 80 if lost
                            Protocol = "HIST", // Mark as history
                            PayloadSnippet = sig.PayloadRaw.Take(50).ToArray(),
                            PayloadHash = sig.Hash,
                            Latitude = null, // Could look up from Country but skipping for speed
                            Longitude = null
                        };
                        history.Add(evt);
                    }
                    else
                    {
                        _logger.LogWarning($"HistoryLoader: Missing signature for hash {log.SignatureHash}");
                    }
                }

                _memoryStore.LoadHistory(history);
                _logger.LogInformation($"Loaded {history.Count} historical events from DB.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load history on startup");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
