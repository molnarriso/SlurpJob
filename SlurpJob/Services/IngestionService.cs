using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using SlurpJob.Models;
using SlurpJob.Networking;
using SlurpJob.Classification;
using SlurpJob.Data;
using SlurpJob.Hubs;
using MaxMind.GeoIP2;
using Microsoft.EntityFrameworkCore;

namespace SlurpJob.Services;

public class IngestionService : BackgroundService
{
    private readonly TcpSponge _tcpSponge;
    private readonly UdpSponge _udpSponge;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHubContext<DashboardHub> _hubContext;
    private readonly IEnumerable<IInboundClassifier> _classifiers;
    private readonly ILogger<IngestionService> _logger;
    private readonly string _geoDbPath;
    private DatabaseReader? _geoReader;
    
    public IngestionService(
        IServiceScopeFactory scopeFactory,
        IHubContext<DashboardHub> hubContext,
        IEnumerable<IInboundClassifier> classifiers,
        ILogger<IngestionService> logger)
    {
        _scopeFactory = scopeFactory;
        _hubContext = hubContext;
        _classifiers = classifiers;
        _logger = logger;
        
        _tcpSponge = new TcpSponge(9000);
        _udpSponge = new UdpSponge(9001);
        
        // Configurable path, default to current dir or specific location
        _geoDbPath = "/opt/slurpjob/GeoLite2-City.mmdb";
    }

    // Stats
    public long TotalEvents => _totalEvents;
    public long ThreatsDetected => _threatsDetected;
    public double EventsPerSecond => _eps;

    private long _totalEvents;
    private long _threatsDetected;
    private double _eps;
    private DateTime _lastEpsUpdate = DateTime.UtcNow;
    private int _eventsSinceLastUpdate;

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        InitializeGeoIp();
        
        _tcpSponge.OnConnectionReceived += async (data) => await HandleConnection(data.SourceIp, data.SourcePort, data.OriginalTargetPort, "TCP", data.Payload, data.Timestamp);
        _udpSponge.OnPacketReceived += async (data) => await HandleConnection(data.SourceIp, data.SourcePort, data.OriginalTargetPort, "UDP", data.Payload, data.Timestamp);
        
        // Run reclassification in background after start
        _ = Task.Run(() => ReclassifyUnclassifiedAsync(cancellationToken), cancellationToken);

        return base.StartAsync(cancellationToken);
    }

    private async Task ReclassifyUnclassifiedAsync(CancellationToken ct)
    {
        try
        {
            _logger.LogInformation("Starting background reclassification of 'Unclassified' entries...");

            using var scope = _scopeFactory.CreateScope();
            var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<SlurpContext>>();
            using var db = factory.CreateDbContext();

            var unclassified = await db.IncidentLogs
                .Include(i => i.Evidence)
                .Where(i => i.ClassifierName == "Unclassified")
                .ToListAsync(ct);

            if (unclassified.Count == 0)
            {
                _logger.LogInformation("No 'Unclassified' entries found for reclassification.");
                return;
            }

            _logger.LogInformation($"Found {unclassified.Count} 'Unclassified' entries. Re-running classifiers...");

            int updatedCount = 0;
            foreach (var incident in unclassified)
            {
                if (ct.IsCancellationRequested) break;
                if (incident.Evidence == null) continue;

                var payload = incident.Evidence.PayloadBlob;
                var results = _classifiers.Select(c => c.Classify(payload, incident.Protocol, incident.TargetPort)).ToList();

                var bestProtocol = results.FirstOrDefault(r => r.Protocol != PayloadProtocol.Unknown)?.Protocol ?? PayloadProtocol.Unknown;
                var bestIntent = results.Where(r => r.Intent != Intent.Unknown)
                                        .OrderByDescending(r => (int)r.Intent)
                                        .FirstOrDefault()?.Intent ?? Intent.Unknown;
                var bestName = results.FirstOrDefault(r => r.Intent != Intent.Unknown)?.Name 
                               ?? results.FirstOrDefault(r => r.Protocol != PayloadProtocol.Unknown)?.Name
                               ?? "Unclassified";

                if (bestName != "Unclassified")
                {
                    incident.PayloadProtocol = bestProtocol.ToString();
                    incident.Intent = bestIntent.ToString();
                    incident.ClassifierName = bestName;
                    updatedCount++;
                }
            }

            if (updatedCount > 0)
            {
                await db.SaveChangesAsync(ct);
                _logger.LogInformation($"Successfully reclassified {updatedCount} incidents.");
            }
            else
            {
                _logger.LogInformation("Finished reclassification. No items were updated.");
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Reclassification task cancelled.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during background reclassification");
        }
    }

    private void InitializeGeoIp()
    {
        try
        {
            if (File.Exists(_geoDbPath))
            {
                _geoReader = new DatabaseReader(_geoDbPath);
                _logger.LogInformation($"Loaded MaxMind DB from {_geoDbPath}");
            }
            else
            {
                _logger.LogWarning($"MaxMind DB not found at {_geoDbPath}. Geo-tagging disabled.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Failed to load MaxMind DB at {_geoDbPath}");
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var t1 = _tcpSponge.StartAsync(stoppingToken);
        var t2 = _udpSponge.StartAsync(stoppingToken);
        
        await Task.WhenAll(t1, t2);
    }

    private async Task HandleConnection(System.Net.IPAddress sourceIp, int sourcePort, int targetPort, string protocol, byte[] payload, DateTime timestamp)
    {
        // Stats Update
        Interlocked.Increment(ref _totalEvents);
        Interlocked.Increment(ref _eventsSinceLastUpdate);
        
        // Simple EPS Calculation
        var now = DateTime.UtcNow;
        if ((now - _lastEpsUpdate).TotalSeconds >= 1)
        {
            var seconds = (now - _lastEpsUpdate).TotalSeconds;
            _eps = _eventsSinceLastUpdate / seconds;
            _eventsSinceLastUpdate = 0;
            _lastEpsUpdate = now;
        }
        // 1. Resolve Country
        string country = "XX";
        if (_geoReader != null)
        {
            try
            {
                if (_geoReader.TryCity(sourceIp, out var response))
                {
                    country = response?.Country?.IsoCode ?? "XX";
                }
            }
            catch { }
        }

        // 2. Classify (run ALL classifiers and merge results)
        var results = _classifiers.Select(c => c.Classify(payload, protocol, targetPort)).ToList();
        
        // Merge: take best Protocol, best Intent, best Name
        var bestProtocol = results.FirstOrDefault(r => r.Protocol != PayloadProtocol.Unknown)?.Protocol ?? PayloadProtocol.Unknown;
        var bestIntent = results.Where(r => r.Intent != Intent.Unknown)
                                .OrderByDescending(r => (int)r.Intent)
                                .FirstOrDefault()?.Intent ?? Intent.Unknown;
        var bestName = results.FirstOrDefault(r => r.Intent != Intent.Unknown)?.Name 
                       ?? results.FirstOrDefault(r => r.Protocol != PayloadProtocol.Unknown)?.Name
                       ?? "Unclassified";
        
        // 3. Create Incident
        var incident = new IncidentLog
        {
            Timestamp = timestamp,
            SourceIp = sourceIp.ToString(),
            CountryCode = country,
            TargetPort = targetPort,
            Protocol = protocol,
            PayloadProtocol = bestProtocol.ToString(),
            Intent = bestIntent.ToString(),
            ClassifierName = bestName,
            Evidence = new EvidenceLocker
            {
                PayloadBlob = payload
            }
        };

        // 4. Persist (Using DB Factory)
        using (var scope = _scopeFactory.CreateScope())
        {
            var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<SlurpContext>>();
            using var db = factory.CreateDbContext();
            db.IncidentLogs.Add(incident); // Cascades to Evidence
            await db.SaveChangesAsync();
        }

        // 5. Push to Dashboard
        var dto = IncidentDto.FromEntity(incident);
        await _hubContext.Clients.All.SendAsync("ReceiveIncident", dto);
        
        // 6. Invoke C# Event (For Blazor Server local)
        OnNewIncident?.Invoke(incident);
        
        _logger.LogInformation($"Ingested: {protocol} {sourceIp} -> {targetPort} [{bestName}]");
        
        if (bestIntent == Intent.Exploit)
        {
            Interlocked.Increment(ref _threatsDetected);
        }
    }

    public event Action<IncidentLog>? OnNewIncident;
}
