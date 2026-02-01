using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SlurpJob.Models;

public enum PayloadProtocol
{
    Unknown = 0,
    HTTP = 1,
    SSH = 2,
    Telnet = 3,
    FTP = 4,
    DNS = 5,
    TLS = 6,
    SIP = 7,
    SSDP = 8,
    RDP = 9,
    JSONRPC = 10,
    Redis = 11,
    RMI = 12,
    T3 = 13,
    Magellan = 14
}

public enum Intent
{
    Unknown = 0,
    Recon = 1,
    Exploit = 2,
    Benign = 3
}

[Table("IncidentLog")]
public class IncidentLog
{
    [Key]
    public long Id { get; set; }
    

    public DateTime Timestamp { get; set; }
    
    public string SourceIp { get; set; } = string.Empty;
    public string CountryCode { get; set; } = "XX";
    public int TargetPort { get; set; }
    public string Protocol { get; set; } = "TCP"; // TCP/UDP (network protocol)
    
    public string PayloadProtocol { get; set; } = "Unknown"; // HTTP, SSH, etc.
    public string Intent { get; set; } = "Unknown"; // Recon, Exploit, etc.
    
    /// <summary>
    /// Stable identifier for attack catalog lookup (e.g., "rdp-bluekeep")
    /// </summary>
    public string ClassifierId { get; set; } = "unknown";
    
    public string ClassifierName { get; set; } = "Unclassified";
    
    // Navigation
    public EvidenceLocker? Evidence { get; set; }
}

[Table("EvidenceLocker")]
public class EvidenceLocker
{
    [Key, ForeignKey("Incident")]
    public long IncidentId { get; set; }
    
    public byte[] PayloadBlob { get; set; } = Array.Empty<byte>();
    
    public IncidentLog? Incident { get; set; }
}
