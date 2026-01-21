using SlurpJob.Models;

namespace SlurpJob.Classification;

public class BasicClassifier : IInboundClassifier
{
    public string Name => "Basic Signatures";

    public ClassificationResult Classify(byte[] payload, string protocol, int targetPort)
    {
        if (payload.Length == 0)
        {
            return new ClassificationResult { Name = "Empty Scan", Tag = IncidentTag.Recon };
        }

        // Convert common payload starts to string for simple matching
        var text = System.Text.Encoding.ASCII.GetString(payload.Take(100).ToArray());

        if (text.Contains("GET") || text.Contains("POST") || text.Contains("HTTP"))
        {
            if (text.Contains("jndi:ldap")) return new ClassificationResult { Name = "Log4J Probe", Tag = IncidentTag.Exploit };
            if (text.Contains(".env")) return new ClassificationResult { Name = "Env File Probe", Tag = IncidentTag.Recon };
            
            return new ClassificationResult { Name = "Generic HTTP", Tag = IncidentTag.Recon };
        }
        
        if (protocol == "UDP" && payload.Length > 0)
        {
             // Simple UDP heuristic
             return new ClassificationResult { Name = "UDP Noise", Tag = IncidentTag.Unknown };
        }

        return ClassificationResult.Unclassified;
    }
}
