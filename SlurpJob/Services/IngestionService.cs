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
        
        return base.StartAsync(cancellationToken);
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
                    country = response.Country.IsoCode ?? "XX";
                }
            }
            catch { }
        }

        // 2. Classify
        var classification = ClassificationResult.Unclassified;
        foreach (var classifier in _classifiers)
        {
            var result = classifier.Classify(payload, protocol, targetPort);
            if (result.Tag != IncidentTag.Unknown)
            {
                classification = result;
                break; // First match wins
            }
        }
        
        // 3. Create Incident
        var incident = new IncidentLog
        {
            Timestamp = timestamp,
            SourceIp = sourceIp.ToString(),
            CountryCode = country,
            TargetPort = targetPort,
            Protocol = protocol,
            PrimaryTag = classification.Tag,
            ClassifierName = classification.Name,
            Evidence = new EvidenceLocker
            {
                PayloadBlob = payload
            }
        };

        // 4. Persist (Scoped DB Context)
        using (var scope = _scopeFactory.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SlurpContext>();
            db.IncidentLogs.Add(incident); // Cascades to Evidence
            await db.SaveChangesAsync();
        }

        // 5. Push to Dashboard
        var dto = IncidentDto.FromEntity(incident);
        await _hubContext.Clients.All.SendAsync("ReceiveIncident", dto);
        
        // 6. Invoke C# Event (For Blazor Server local)
        OnNewIncident?.Invoke(incident);
        
        _logger.LogInformation($"Ingested: {protocol} {sourceIp} -> {targetPort} [{classification.Name}]");
        
        if (classification.Tag != IncidentTag.Unknown && classification.Tag != IncidentTag.Garbage)
        {
            Interlocked.Increment(ref _threatsDetected);
        }
    }

    public event Action<IncidentLog>? OnNewIncident;
}
