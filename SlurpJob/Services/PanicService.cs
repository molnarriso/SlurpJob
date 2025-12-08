using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SlurpJob.Services;

public class PanicService : BackgroundService
{
    private readonly IngestionService _ingestionService;
    private readonly ILogger<PanicService> _logger;

    public PanicService(IngestionService ingestionService, ILogger<PanicService> logger)
    {
        _ingestionService = ingestionService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(1000, stoppingToken);
            
            // Check Traffic (Threshold: 50 Mbps)
            if (_ingestionService.CurrentMbps > 50)
            {
                _logger.LogCritical($"High Traffic Detected: {_ingestionService.CurrentMbps:F2} Mbps. Triggering Panic Button.");
                TriggerPanic();
                
                // Wait a bit before checking again to avoid spamming
                await Task.Delay(60000, stoppingToken);
            }
        }
    }

    private void TriggerPanic()
    {
        try
        {
            // Flush iptables nat table to stop redirection
            // This effectively "unplugs" the sensor
            var psi = new ProcessStartInfo
            {
                FileName = "iptables",
                Arguments = "-t nat -F",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            process?.WaitForExit();
            
            _logger.LogCritical("PANIC EXECUTED: iptables -t nat -F");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute Panic Button");
        }
    }
}
