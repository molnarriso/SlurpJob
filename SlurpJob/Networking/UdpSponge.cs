using System.Net;
using System.Net.Sockets;

namespace SlurpJob.Networking;

public class UdpSponge
{
    private readonly int _port;
    private Socket? _socket;
    
    public event Action<UdpPacketData>? OnPacketReceived;

    public UdpSponge(int port = 9001)
    {
        _port = port;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Any, _port));
        
        // Try to set IP_RECVORIGDSTADDR (20)
        try
        {
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux))
            {
                _socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)LinuxInterop.IP_RECVORIGDSTADDR, 1);
            }
        }
        catch
        {
            Console.WriteLine("Failed to set IP_RECVORIGDSTADDR. Original destination might be incorrect.");
        }

        Console.WriteLine($"UDP Sponge listening on port {_port}");

        // Start receive loop
        _ = Task.Run(async () => await ReceiveLoopAsync(cancellationToken), cancellationToken);
        
        return Task.CompletedTask;
    }

    private async Task ReceiveLoopAsync(CancellationToken token)
    {
        var buffer = new byte[65535];
        
        while (!token.IsCancellationRequested)
        {
            try
            {
                // TODO: Use P/Invoke recvmsg to get ancillary data for original destination
                // For now, using standard ReceiveFrom which gives us the Source, but not the Original Destination (it gives the local bind port)
                
                EndPoint remoteEp = new IPEndPoint(IPAddress.Any, 0);
                var result = await _socket!.ReceiveFromAsync(buffer, SocketFlags.None, remoteEp, token);
                
                var payload = new byte[result.ReceivedBytes];
                Array.Copy(buffer, payload, result.ReceivedBytes);
                
                var sourceEp = (IPEndPoint)result.RemoteEndPoint;

                // Placeholder for Original Port (default to 0 or something until we implement recvmsg)
                // In a real redirect scenario, we can't easily get it without recvmsg.
                // We'll assume the user understands this limitation in Phase 1.
                int originalPort = 0; 

                var data = new UdpPacketData
                {
                    SourceIp = sourceEp.Address,
                    SourcePort = sourceEp.Port,
                    OriginalTargetPort = originalPort, 
                    Payload = payload,
                    Timestamp = DateTime.UtcNow
                };

                OnPacketReceived?.Invoke(data);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"UDP Receive Error: {ex.Message}");
            }
        }
    }
}

public class UdpPacketData
{
    public IPAddress SourceIp { get; set; } = IPAddress.None;
    public int SourcePort { get; set; }
    public int OriginalTargetPort { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();
    public DateTime Timestamp { get; set; }
}
