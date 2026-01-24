using System.Globalization;
using CsvHelper;
using CsvHelper.Configuration;

namespace SlurpJob.Services;

public class PortInfo
{
    public string? TcpShort { get; set; }
    public string? TcpFull { get; set; }
    public string? UdpShort { get; set; }
    public string? UdpFull { get; set; }
}

public class PortTableService
{
    private readonly PortInfo[] _ports = new PortInfo[65536];
    private readonly ILogger<PortTableService> _logger;

    public PortTableService(ILogger<PortTableService> logger, IHostEnvironment env)
    {
        _logger = logger;
        LoadPortTable();
    }

    private void LoadPortTable()
    {
        try
        {
            string fileName = "port_table.csv";
            string? path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName);
            
            if (!File.Exists(path))
            {
                // Try to find it in the working directory
                path = fileName;
            }

            if (!File.Exists(path))
            {
                // Search up for development/test environments
                var currentDir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
                while (currentDir != null && !File.Exists(Path.Combine(currentDir.FullName, fileName)))
                {
                    currentDir = currentDir.Parent;
                }
                
                if (currentDir != null)
                {
                    path = Path.Combine(currentDir.FullName, fileName);
                }
            }

            if (path == null || !File.Exists(path))
            {
                _logger.LogWarning("Port table CSV not found.");
                return;
            }

            _logger.LogInformation("Loading port table from {Path}", Path.GetFullPath(path));

            var config = new CsvConfiguration(CultureInfo.InvariantCulture)
            {
                HasHeaderRecord = true,
                MissingFieldFound = null,
                HeaderValidated = null,
            };

            using var reader = new StreamReader(path);
            using var csv = new CsvReader(reader, config);

            csv.Read();
            csv.ReadHeader();

            int count = 0;
            while (csv.Read())
            {
                try
                {
                    int port = csv.GetField<int>("Port");
                    if (port < 0 || port > 65535) continue;

                    string tcpFlag = csv.GetField<string>("TCP") ?? "";
                    string udpFlag = csv.GetField<string>("UDP") ?? "";
                    string description = csv.GetField<string>("Description") ?? "";
                    string shortDescription = csv.GetField<string>("ShortDescription") ?? "";

                    if (string.IsNullOrWhiteSpace(shortDescription) && !string.IsNullOrWhiteSpace(description))
                    {
                        shortDescription = description;
                    }

                    if (string.IsNullOrWhiteSpace(shortDescription)) continue;

                    var info = _ports[port] ??= new PortInfo();

                    bool loaded = false;
                    if (tcpFlag.Equals("Yes", StringComparison.OrdinalIgnoreCase))
                    {
                        info.TcpShort = shortDescription;
                        info.TcpFull = description;
                        loaded = true;
                    }

                    if (udpFlag.Equals("Yes", StringComparison.OrdinalIgnoreCase))
                    {
                        info.UdpShort = shortDescription;
                        info.UdpFull = description;
                        loaded = true;
                    }
                    
                    if (loaded) count++;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error parsing port table row");
                }
            }

            _logger.LogInformation("Port table loaded successfully. Total ports with info: {Count}", count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load port table");
        }
    }

    public (string? Short, string? Full) GetPortDescription(int port, string protocol)
    {
        if (port < 0 || port > 65535) return (null, null);

        var info = _ports[port];
        if (info == null) return (null, null);

        if (protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
        {
            return (info.TcpShort, info.TcpFull);
        }
        else if (protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
        {
            return (info.UdpShort, info.UdpFull);
        }

        return (null, null);
    }
}
