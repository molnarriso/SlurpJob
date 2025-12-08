using System.Net;
using System.Net.Sockets;

namespace SlurpJob.Networking;

public class TcpSponge
{
    private readonly int _port;
    private TcpListener? _listener;
    
    // Event to notify ingestion service
    public event Action<TcpConnectionData>? OnConnectionReceived;

    public TcpSponge(int port = 9000)
    {
        _port = port;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _listener = new TcpListener(IPAddress.Any, _port);
        _listener.Start();
        Console.WriteLine($"TCP Sponge listening on port {_port}");

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(cancellationToken);
                _ = HandleClientAsync(client, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Graceful shutdown
        }
        catch (Exception ex)
        {
            Console.WriteLine($"TCP Sponge Error: {ex.Message}");
        }
        finally
        {
            _listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken token)
    {
        using (client)
        {
            try
            {
                var socket = client.Client;
                var remoteEp = socket.RemoteEndPoint as IPEndPoint;
                var originalEp = LinuxInterop.GetOriginalDestination(socket);
                
                // Fallback for non-Linux or failed lookup
                if (originalEp == null)
                {
                     var local = socket.LocalEndPoint as IPEndPoint;
                     originalEp = local;
                }

                if (remoteEp == null || originalEp == null) return;

                // Read up to 32KB (Peek)
                var stream = client.GetStream();
                var buffer = new byte[32 * 1024];
                
                // 5s timeout to receive initial data (was 2s)
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(5)); 

                int bytesRead = 0;
                try 
                {
                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                }
                catch (OperationCanceledException) 
                {
                    // Timeout or cancelled
                }

                // Console.WriteLine($"TcpSponge: {remoteEp} -> {originalEp} ({bytesRead} bytes)");

                var payload = new byte[bytesRead];
                Array.Copy(buffer, payload, bytesRead);

                var data = new TcpConnectionData
                {
                    SourceIp = remoteEp.Address,
                    SourcePort = remoteEp.Port,
                    OriginalTargetPort = originalEp.Port,
                    Payload = payload,
                    Timestamp = DateTime.UtcNow
                };

                // Notify Ingestion (Log everything)
                OnConnectionReceived?.Invoke(data);

                // PROXY LOGIC
                if (originalEp.Port == 80 && bytesRead > 0)
                {
                    // Console.WriteLine($"TcpSponge: Proxying {remoteEp} to Backend");
                    await ProxyToBackend(client, payload, token);
                }
                else if (originalEp.Port == 80)
                {
                    Console.WriteLine($"TcpSponge: Dropped Port 80 connection from {remoteEp} (0 bytes read)");
                }
            }
            catch (Exception ex)
            {
                 Console.WriteLine($"TcpSponge Error: {ex.Message}");
            }
        }
    }

    private async Task ProxyToBackend(TcpClient client, byte[] initialPayload, CancellationToken token)
    {
        try
        {
            client.NoDelay = true; // Disable Nagle

            using var backend = new TcpClient();
            backend.NoDelay = true; // Disable Nagle

            // Connect to local Kestrel
            await backend.ConnectAsync("127.0.0.1", 5000, token);
            
            var backendStream = backend.GetStream();
            var clientStream = client.GetStream();

            // Forward initial payload
            await backendStream.WriteAsync(initialPayload, token);

            // Bi-directional copy
            using var tunnelCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            
            var clientToBackend = CopyStream(clientStream, backendStream, tunnelCts.Token);
            var backendToClient = CopyStream(backendStream, clientStream, tunnelCts.Token);

            await Task.WhenAny(clientToBackend, backendToClient);
            tunnelCts.Cancel(); // Cancel the other direction
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Proxy Error: {ex.Message}");
        }
    }

    private async Task CopyStream(NetworkStream source, NetworkStream destination, CancellationToken token)
    {
        try
        {
            await source.CopyToAsync(destination, token);
        }
        catch { }
    }
}

public class TcpConnectionData
{
    public IPAddress SourceIp { get; set; } = IPAddress.None;
    public int SourcePort { get; set; }
    public int OriginalTargetPort { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();
    public DateTime Timestamp { get; set; }
}
