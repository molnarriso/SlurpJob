using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SlurpyHoneypot
{
    public class ConnectionHandler
    {
        private readonly InfluxDbLogger _influxDbLogger;
        private readonly DataLimiter _dataLimiter;

        public ConnectionHandler(InfluxDbLogger influxDbLogger, DataLimiter dataLimiter)
        {
            _influxDbLogger = influxDbLogger;
            _dataLimiter = dataLimiter;
        }

        public async Task HandleTcpConnection(TcpClient client)
        {
            using (var stream = client.GetStream())
            {
                var (isHttps, memoryStream) = await IsHttpsConnection(stream);
                if (memoryStream == null)
                {
                    // Connection closed or terminated before we could read the first byte
                    return;
                }

                using (memoryStream)
                {
                    // Mock methods for SSL termination and forwarding
                    if (isHttps)
                    {
                        await MockSslTerminationAndForwarding(client, memoryStream);
                    }
                    else
                    {
                        await MockForwarding(client, memoryStream);
                    }

                    // After connection is closed or terminated, log the complete data
                    await LogConnectionData(client, memoryStream.ToArray());
                }
            }
        }

        public async Task HandleUdpConnection(UdpClient client, IPEndPoint remoteEndPoint, byte[] receivedData)
        {
            // TODO: Add error handling and logging
            if (_dataLimiter.IsLimitExceeded(receivedData.Length))
            {
                // Log only the first part of the datagram and a hash of the whole datagram
                // ...
            }
            else
            {
                // Log the entire datagram
                // ...
            }
        }

        private async Task<(bool, MemoryStream)> IsHttpsConnection(NetworkStream stream)
        {
            if (!stream.CanRead || !stream.DataAvailable)
            {
                return (false, null);
            }

            var memoryStream = new MemoryStream();
            var firstByte = new byte[1];
            int bytesRead = await stream.ReadAsync(firstByte, 0, 1);
            if (bytesRead == 0)
            {
                return (false, null);
            }

            memoryStream.Write(firstByte, 0, bytesRead);
            return (firstByte[0] == 0x16, memoryStream);
        }

        private async Task MockSslTerminationAndForwarding(TcpClient client, MemoryStream memoryStream)
        {
            // TODO: Implement SSL termination and forwarding logic
        }

        private async Task MockForwarding(TcpClient client, MemoryStream memoryStream)
        {
            // TODO: Implement forwarding logic
        }


        private async Task LogConnectionData(TcpClient client, byte[] data)
        {
            var remoteEndPoint = client.Client.RemoteEndPoint as IPEndPoint;
            string protocol = "TCP";

            int dataSize = data.Length;
            byte[] partialData = dataSize > _dataLimiter.MaxDataSize ? data.Take(_dataLimiter.MaxDataSize).ToArray() : data;
            string dataHash = Convert.ToBase64String(SHA256.Create().ComputeHash(data));

            ConnectionDetails connectionDetails = new ConnectionDetails
            {
                RemoteEndPoint = remoteEndPoint,
                Protocol = protocol,
                DataSize = dataSize,
                PartialData = partialData,
                DataHash = dataHash,
                Timestamp = DateTime.UtcNow
            };

            await _influxDbLogger.LogEvent(connectionDetails,"connection");
        }
    }
}
