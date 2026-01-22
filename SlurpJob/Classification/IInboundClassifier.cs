using SlurpJob.Models;

namespace SlurpJob.Classification;

public interface IInboundClassifier
{
    string Name { get; }
    ClassificationResult Classify(byte[] payload, string networkProtocol, int targetPort);
}

public class ClassificationResult
{
    public string Name { get; set; } = string.Empty;
    public PayloadProtocol Protocol { get; set; } = PayloadProtocol.Unknown;
    public Intent Intent { get; set; } = Intent.Unknown;
    
    public static ClassificationResult Unclassified => new();
}
