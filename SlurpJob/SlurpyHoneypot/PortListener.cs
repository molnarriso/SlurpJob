using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SlurpyHoneypot
{
    public class PortListener
    {
        public delegate Task TcpConnectionHandlerDelegate(TcpClient client);
        public delegate Task UdpConnectionHandlerDelegate(UdpClient client, IPEndPoint remoteEndPoint, byte[] receivedData);

        private readonly List<int> _tcpPorts;
        private readonly List<int> _udpPorts;
        private readonly TcpConnectionHandlerDelegate _tcpConnectionHandler;
        private readonly UdpConnectionHandlerDelegate _udpConnectionHandler;
        private readonly ILogger _logger;
        private CancellationTokenSource _cancellationTokenSource;

        public PortListener(List<int> tcpPorts, List<int> udpPorts, TcpConnectionHandlerDelegate tcpConnectionHandler, UdpConnectionHandlerDelegate udpConnectionHandler, ILogger logger)
        {
            _tcpPorts = tcpPorts;
            _udpPorts = udpPorts;
            _tcpConnectionHandler = tcpConnectionHandler;
            _udpConnectionHandler = udpConnectionHandler;
            _logger = logger;
        }

        public async Task StartListening()
        {
            _cancellationTokenSource = new CancellationTokenSource();

            var tcpListeners = StartTcpListeners();
            var udpListeners = StartUdpListeners();

            await Task.WhenAll(tcpListeners.Concat(udpListeners));
        }

        public void StopListening()
        {
            _cancellationTokenSource.Cancel();
        }

        private IEnumerable<Task> StartTcpListeners()
        {
            var tasks = new List<Task>();

            foreach (var port in _tcpPorts)
            {
                var listener = new TcpListener(IPAddress.Any, port);
                listener.Start();

                tasks.Add(Task.Run(async () =>
                {
                    while (!_cancellationTokenSource.IsCancellationRequested)
                    {
                        try
                        {
                            var client = await listener.AcceptTcpClientAsync();
                            _ = _tcpConnectionHandler(client);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error in TCP listener on port {port}");
                        }
                    }

                    listener.Stop();
                }, _cancellationTokenSource.Token));
            }

            return tasks;
        }

        private IEnumerable<Task> StartUdpListeners()
        {
            var tasks = new List<Task>();

            foreach (var port in _udpPorts)
            {
                var client = new UdpClient(port);

                tasks.Add(Task.Run(async () =>
                {
                    while (!_cancellationTokenSource.IsCancellationRequested)
                    {
                        try
                        {
                            var result = await client.ReceiveAsync();
                            _ = _udpConnectionHandler(client, result.RemoteEndPoint, result.Buffer);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, $"Error in UDP listener on port {port}");
                        }
                    }

                    client.Close();
                }, _cancellationTokenSource.Token));
            }

            return tasks;
        }
    }
}