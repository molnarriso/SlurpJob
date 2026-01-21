using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SlurpJob.Models;

public enum IncidentTag
{
    Unknown = 0,
    Recon = 1,
    Exploit = 2,
    Garbage = 3,
    Misc = 4
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
    public string Protocol { get; set; } = "TCP"; // TCP/UDP
    
    public IncidentTag PrimaryTag { get; set; } = IncidentTag.Unknown;
    
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
