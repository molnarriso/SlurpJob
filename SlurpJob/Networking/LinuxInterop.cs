using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SlurpJob.Networking;

public static class LinuxInterop
{
    // SOL_IP = 0
    public const int SOL_IP = 0;
    
    // SO_ORIGINAL_DST = 80 (defined in linux/netfilter_ipv4.h)
    public const int SO_ORIGINAL_DST = 80;

    // IP_RECVORIGDSTADDR = 20 (defined in linux/in.h)
    // Used with setsockopt to enable receiving the original destination address in ancillary data.
    public const int IP_RECVORIGDSTADDR = 20;

    // IP_ORIGDSTADDR = 20 (defined in linux/in.h)
    // The cmsg_type for the ancillary data containing the original destination.
    public const int IP_ORIGDSTADDR = 20;

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SockAddrIn
    {
        public ushort sin_family;
        public ushort sin_port;
        public uint sin_addr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] sin_zero;
    }

    [DllImport("libc", SetLastError = true)]
    public static extern int getsockopt(int sockfd, int level, int optname, out SockAddrIn optval, ref int optlen);

    public static IPEndPoint? GetOriginalDestination(Socket socket)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return null; // Not supported on non-Linux
        }

        try
        {
            int fd = (int)socket.Handle;
            SockAddrIn addr = new SockAddrIn();
            int len = Marshal.SizeOf(addr);

            int result = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, out addr, ref len);

            if (result == 0)
            {
                // Convert port from Network Byte Order (Big Endian) to Host Byte Order
                ushort port = (ushort)IPAddress.NetworkToHostOrder((short)addr.sin_port);
                long ipAddress = addr.sin_addr; // Already in correct format for IPAddress ctor (long)
                
                return new IPEndPoint(new IPAddress(ipAddress), port);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting original destination: {ex.Message}");
        }

        return null;
    }
}
