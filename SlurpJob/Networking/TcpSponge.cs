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
                
                // 2s timeout to receive initial data (fast fail for scanners)
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(2)); 

                int bytesRead = 0;
                try 
                {
                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                }
                catch (OperationCanceledException) 
                {
                    // Timeout or cancelled
                }

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
                // Only proxy if:
                // 1. Target Port is 80 (HTTP)
                // 2. We have data
                // 3. Data looks like HTTP (GET/POST/etc)
                if (originalEp.Port == 80 && bytesRead > 0 && IsHttp(payload))
                {
                    await ProxyToBackend(client, payload, token);
                }
            }
            catch (Exception ex)
            {
                // Console.WriteLine($"Client Error: {ex.Message}");
            }
        }
    }

    private bool IsHttp(byte[] data)
    {
        if (data.Length < 4) return false;
        // Simple check for common HTTP verbs
        var s = System.Text.Encoding.ASCII.GetString(data, 0, Math.Min(data.Length, 10));
        return s.StartsWith("GET ") || s.StartsWith("POST ") || s.StartsWith("HEAD ") || 
               s.StartsWith("PUT ") || s.StartsWith("DELETE ") || s.StartsWith("OPTIONS ");
    }

    private async Task ProxyToBackend(TcpClient client, byte[] initialPayload, CancellationToken token)
    {
        try
        {
            using var backend = new TcpClient();
            // Connect to local Kestrel
            await backend.ConnectAsync("127.0.0.1", 5000, token);
            
            var backendStream = backend.GetStream();
            var clientStream = client.GetStream();

            // Forward initial payload
            await backendStream.WriteAsync(initialPayload, token);

            // Bi-directional copy
            // We use a larger timeout for the tunnel
            using var tunnelCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            
            var clientToBackend = CopyStream(clientStream, backendStream, tunnelCts.Token);
            var backendToClient = CopyStream(backendStream, clientStream, tunnelCts.Token);

            await Task.WhenAny(clientToBackend, backendToClient);
            tunnelCts.Cancel(); // Cancel the other direction
        }
        catch
        {
            // Proxy error, close connection
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
