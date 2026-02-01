using System.Text;

namespace SlurpJob.Classification.Parsers;

/// <summary>
/// Parses Java RMI and serialized object payloads into structured fields.
/// </summary>
public class RMIParser : IPayloadParser
{
    // JRMI magic bytes
    private static readonly byte[] JrmiMagic = { 0x4A, 0x52, 0x4D, 0x49 }; // "JRMI"
    
    // Java serialized object magic
    private static readonly byte[] JavaSerialMagic = { 0xAC, 0xED, 0x00, 0x05 };
    
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
                byte version = payload[4];
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
