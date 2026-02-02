using System.Net;
using System.Net.Sockets;

namespace SlurpJob.Networking;

public static class IpMatcher
{
    public static bool IsMatch(string ipString, IEnumerable<string> cidrList)
    {
        if (!IPAddress.TryParse(ipString, out var ip))
        {
            return false;
        }
        
        foreach (var cidr in cidrList)
        {
            if (IsInRange(ip, cidr))
            {
                return true;
            }
        }
        
        return false;
    }

    private static bool IsInRange(IPAddress ip, string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network) || !int.TryParse(parts[1], out var prefixLength))
        {
            return false;
        }

        if (ip.AddressFamily != network.AddressFamily)
        {
            return false;
        }

        var ipBytes = ip.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        
        // Check matching bits
        int bitsToCheck = prefixLength;
        for (int i = 0; i < ipBytes.Length; i++)
        {
            if (bitsToCheck >= 8)
            {
                if (ipBytes[i] != networkBytes[i]) return false;
                bitsToCheck -= 8;
            }
            else if (bitsToCheck > 0)
            {
                int mask = ~(255 >> bitsToCheck);
                if ((ipBytes[i] & mask) != (networkBytes[i] & mask)) return false;
                bitsToCheck = 0;
            }
        }

        return true;
    }
}
