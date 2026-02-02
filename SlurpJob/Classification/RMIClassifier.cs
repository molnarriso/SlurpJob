using SlurpJob.Models;
using System.Text;

namespace SlurpJob.Classification;

/// <summary>
/// Detects Java RMI (Remote Method Invocation) protocol.
/// Signature: First 4 bytes = "JRMI" (0x4A524D49)
/// Intent: Exploit (Java deserialization attacks, CVE-2017-3241)
/// </summary>
public class RMIClassifier : IInboundClassifier
{
    public string Id => "RMI";

    // JRMI magic bytes
    private static readonly byte[] JrmiMagic = { 0x4A, 0x52, 0x4D, 0x49 }; // "JRMI"
    
    // Alternative: serialized Java object (used in some RMI attacks)
    private static readonly byte[] JavaSerialMagic = { 0xAC, 0xED, 0x00, 0x05 };

    public ClassificationResult Classify(byte[] payload, string sourceIp, string networkProtocol, int targetPort)
    {
        if (payload.Length < 4) return ClassificationResult.Unclassified;

        // Check for JRMI magic
        if (payload[0] == JrmiMagic[0] && payload[1] == JrmiMagic[1] &&
            payload[2] == JrmiMagic[2] && payload[3] == JrmiMagic[3])
        {
            // Check for protocol version after JRMI header
            string attackType = "Java RMI Probe";
            
            if (payload.Length >= 7)
            {
                // Byte 4 is protocol version, byte 5-6 are additional info
                // Version 0x00 0x01 or 0x00 0x02 are common
                byte version = payload[4];
                if (version == 0x00 && payload.Length >= 6)
                {
                    byte subversion = payload[5];
                    attackType = subversion switch
                    {
                        0x01 => "Java RMI StreamProtocol",
                        0x02 => "Java RMI SingleOpProtocol",
                        0x4B => "Java RMI Multiplex", // 'K'
                        0x4C => "Java RMI Call", // 'L'  
                        0x4D => "Java RMI DGC", // 'M' - Distributed Garbage Collection
                        0x4E => "Java RMI Return", // 'N'
                        _ => "Java RMI Probe"
                    };
                }
            }

            return new ClassificationResult
            {
                AttackId = "java-rmi",
                Name = attackType,
                Protocol = PayloadProtocol.RMI,
                Intent = Intent.Exploit
            };
        }

        // Check for Java serialized object (often used in deserialization attacks)
        if (payload[0] == JavaSerialMagic[0] && payload[1] == JavaSerialMagic[1] &&
            payload[2] == JavaSerialMagic[2] && payload[3] == JavaSerialMagic[3])
        {
            // Check for known gadget chains
            var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 512));
            
            string attackType = "Java Deserialization";
            
            if (text.Contains("CommonsCollections") || text.Contains("org.apache.commons"))
                attackType = "Java Deser CommonsCollections";
            else if (text.Contains("ysoserial"))
                attackType = "Java Deser ysoserial";
            else if (text.Contains("JRMPClient"))
                attackType = "Java Deser JRMP (CVE-2017-3241)";
            else if (text.Contains("Spring"))
                attackType = "Java Deser Spring";

            return new ClassificationResult
            {
                AttackId = "java-rmi",
                Name = attackType,
                Protocol = PayloadProtocol.RMI,
                Intent = Intent.Exploit
            };
        }

        return ClassificationResult.Unclassified;
    }
    
    public ParsedPayload? Parse(byte[] payload)
    {
        if (payload.Length < 4) return null;
        
        var result = new ParsedPayload();
        
        // Check for JRMI magic
        if (payload[0] == JrmiMagic[0] && payload[1] == JrmiMagic[1] &&
            payload[2] == JrmiMagic[2] && payload[3] == JrmiMagic[3])
        {
            result.Fields.Add(("Protocol", "Java RMI (JRMI)"));
            result.Fields.Add(("Magic", "JRMI (0x4A524D49)"));
            
            if (payload.Length >= 6)
            {
                byte subversion = payload[5];
                string protoType = subversion switch
                {
                    0x01 => "StreamProtocol",
                    0x02 => "SingleOpProtocol",
                    0x4B => "Multiplex",
                    0x4C => "Call",
                    0x4D => "DGC (Distributed GC)",
                    0x4E => "Return",
                    _ => $"Unknown (0x{subversion:X2})"
                };
                result.Fields.Add(("Sub-Protocol", protoType));
            }
            return result;
        }
        
        // Check for Java serialized object
        if (payload[0] == JavaSerialMagic[0] && payload[1] == JavaSerialMagic[1] &&
            payload[2] == JavaSerialMagic[2] && payload[3] == JavaSerialMagic[3])
        {
            result.Fields.Add(("Protocol", "Java Serialized Object"));
            result.Fields.Add(("Magic", "0xACED0005"));
            
            // Check for known gadget chains
            var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 512));
            
            if (text.Contains("CommonsCollections") || text.Contains("org.apache.commons"))
                result.Fields.Add(("Gadget Chain", "CommonsCollections"));
            else if (text.Contains("ysoserial"))
                result.Fields.Add(("Gadget Chain", "ysoserial"));
            else if (text.Contains("JRMPClient"))
                result.Fields.Add(("Gadget Chain", "JRMP (CVE-2017-3241)"));
            else if (text.Contains("Spring"))
                result.Fields.Add(("Gadget Chain", "Spring Framework"));
            
            return result;
        }
        
        return null;
    }
}
