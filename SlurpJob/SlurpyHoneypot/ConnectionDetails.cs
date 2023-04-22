using System;
using System.Net;

namespace SlurpyHoneypot
{
    public class ConnectionDetails
    {
        public IPEndPoint RemoteEndPoint { get; init; }
        public DateTime Timestamp { get; init; }
        public string Protocol { get; init; }
        public int DataSize { get; init; }
        public byte[] PartialData { get; init; }
        public string DataHash { get; init; }

        public ConnectionDetails() { }
        public ConnectionDetails(IPEndPoint remoteEndPoint, DateTime timestamp, string protocol, int dataSize, byte[] partialData, string dataHash)
        {
            RemoteEndPoint = remoteEndPoint;
            Timestamp = timestamp;
            Protocol = protocol;
            DataSize = dataSize;
            PartialData = partialData;
            DataHash = dataHash;
        }
    }
}