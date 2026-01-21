using SlurpJob.Models;

namespace SlurpJob.Classification;

public interface IInboundClassifier
{
    string Name { get; }
    ClassificationResult Classify(byte[] payload, string protocol, int targetPort);
}

public class ClassificationResult
{
    public string Name { get; set; } = string.Empty;
    public IncidentTag Tag { get; set; } = IncidentTag.Unknown;
    
    public static ClassificationResult Unclassified => new() { Name = "Unclassified", Tag = IncidentTag.Unknown };
}
