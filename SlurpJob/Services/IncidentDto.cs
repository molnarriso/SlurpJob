using SlurpJob.Models;

namespace SlurpJob.Services;

public class IncidentDto
{
    public DateTime Timestamp { get; set; }
    public string SourceIp { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public int TargetPort { get; set; }
    public string Protocol { get; set; } = "";
    public string PayloadProtocol { get; set; } = "";
    public string Intent { get; set; } = "";
    public string ClassifierName { get; set; } = "";
    public byte[] PayloadBlob { get; set; } = Array.Empty<byte>();

    public static IncidentDto FromEntity(IncidentLog log)
    {
        return new IncidentDto
        {
            Timestamp = log.Timestamp,
            SourceIp = log.SourceIp,
            CountryCode = log.CountryCode,
            TargetPort = log.TargetPort,
            Protocol = log.Protocol,
            PayloadProtocol = log.PayloadProtocol,
            Intent = log.Intent,
            ClassifierName = log.ClassifierName,
            PayloadBlob = log.Evidence?.PayloadBlob ?? Array.Empty<byte>()
        };
    }
}
