using System.Security.Cryptography;
using MaxMind.GeoIP2;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SlurpJob.Models;
using SlurpJob.Networking;

namespace SlurpJob.Services;

public class IngestionService : BackgroundService
{
    private readonly TcpSponge _tcpSponge;
    private readonly UdpSponge _udpSponge;
    private readonly MemoryStore _memoryStore;
    private readonly ILogger<IngestionService> _logger;
    private readonly string _geoDbPath;
    private DatabaseReader? _geoReader;
    
    // Metrics
    private long _totalBytesReceived;
    private DateTime _lastMetricReset = DateTime.UtcNow;
    public double CurrentMbps { get; private set; }

    public IngestionService(MemoryStore memoryStore, ILogger<IngestionService> logger)
    {
        _memoryStore = memoryStore;
        _logger = logger;
        _tcpSponge = new TcpSponge(9000);
        _udpSponge = new UdpSponge(9001);
        
        // Configurable path, default to current dir or specific location
        // Hardcoded for deployment stability
        _geoDbPath = "/opt/slurpjob/GeoLite2-City.mmdb";
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        InitializeGeoIp();
        
        _tcpSponge.OnConnectionReceived += HandleTcpConnection;
        _udpSponge.OnPacketReceived += HandleUdpPacket;
        
        return base.StartAsync(cancellationToken);
    }

    private void InitializeGeoIp()
    {
        try
        {
            _logger.LogInformation($"Initializing GeoIP. Path: {_geoDbPath}");
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
        var t3 = MetricLoop(stoppingToken);
        
        await Task.WhenAll(t1, t2, t3);
    }

    private async Task MetricLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await Task.Delay(1000, token);
            var now = DateTime.UtcNow;
            var seconds = (now - _lastMetricReset).TotalSeconds;
            if (seconds > 0)
            {
                var bytes = Interlocked.Exchange(ref _totalBytesReceived, 0);
                var mbps = (bytes * 8) / (1000 * 1000) / seconds;
                CurrentMbps = mbps;
                _lastMetricReset = now;
            }
        }
    }

    private void HandleTcpConnection(TcpConnectionData data)
    {
        Interlocked.Add(ref _totalBytesReceived, data.Payload.Length);
        ProcessEvent(data.SourceIp, data.SourcePort, data.OriginalTargetPort, "TCP", data.Payload, data.Timestamp);
    }

    private void HandleUdpPacket(UdpPacketData data)
    {
        Interlocked.Add(ref _totalBytesReceived, data.Payload.Length);
        ProcessEvent(data.SourceIp, data.SourcePort, data.OriginalTargetPort, "UDP", data.Payload, data.Timestamp);
    }

    private void ProcessEvent(System.Net.IPAddress sourceIp, int sourcePort, int targetPort, string protocol, byte[] payload, DateTime timestamp)
    {
        // 1. Resolve Country & Location
        string country = "XX";
        double? lat = null;
        double? lon = null;
        
        if (_geoReader != null)
        {
            try
            {
                if (_geoReader.TryCity(sourceIp, out var response))
                {
                    country = response.Country.IsoCode ?? "XX";
                    lat = response.Location.Latitude;
                    lon = response.Location.Longitude;
                }
            }
            catch { }
        }

        // 2. Compute Hash
        string hashInput;
        if (payload.Length == 0 && protocol == "UDP")
        {
            hashInput = $"{protocol}|EMPTY|{targetPort}";
        }
        else
        {
            using var sha = SHA256.Create();
            var hashBytes = sha.ComputeHash(payload);
            hashInput = Convert.ToHexString(hashBytes);
        }
        
        // 3. SNI Extraction (Basic placeholder)
        string? sni = null;

        // 4. Create LiveEvent
        var evt = new LiveEvent
        {
            Timestamp = timestamp,
            SourceCountry = country,
            SourceIp = sourceIp,
            TargetPort = targetPort,
            Protocol = protocol,
            PayloadSnippet = payload.Take(50).ToArray(),
            PayloadSize = payload.Length, // Store actual full size
            PayloadHash = hashInput,
            Latitude = lat,
            Longitude = lon
        };

        // 5. Push to MemoryStore
        _memoryStore.AddEvent(evt, hashInput, payload, sni);
        
        if (protocol == "TCP" && targetPort == 80)
        {
            Console.WriteLine($"Ingestion: Processed HTTP event from {sourceIp} (Hash: {hashInput})");
        }
    }
}
