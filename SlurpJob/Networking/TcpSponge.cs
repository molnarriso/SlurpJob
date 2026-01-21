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

                // Read up to 16KB (Spec Limit)
                var stream = client.GetStream();
                var buffer = new byte[16 * 1024];
                
                // 15s timeout to receive initial data (Spec)
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(TimeSpan.FromSeconds(15)); 

                int bytesRead = 0;
                try 
                {
                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                }
                catch (OperationCanceledException) { }
                catch (IOException) { }

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

                OnConnectionReceived?.Invoke(data);
            }
            catch (Exception ex)
            {
                 Console.WriteLine($"TcpSponge Error: {ex.Message}");
            }
        }
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
