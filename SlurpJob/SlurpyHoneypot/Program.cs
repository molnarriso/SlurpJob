using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace SlurpyHoneypot
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var configuration = new Configuration();
            var logger = new InfluxDbLogger(configuration.GetSetting<string>("InfluxDbConnectionString"));

            var allPorts = Enumerable.Range(1, 65535).ToList();
            var usedTcpPorts = GetUsedTcpPorts();
            var usedUdpPorts = GetUsedUdpPorts();

            var tcpPorts = allPorts.Except(usedTcpPorts).ToList();
            var udpPorts = allPorts.Except(usedUdpPorts).ToList();

            var connectionHandler = new ConnectionHandler(logger);
            var portListener = new PortListener(
                tcpPorts,
                udpPorts,
                client => connectionHandler.HandleTcpConnection(client),
                (client, remoteEndPoint, receivedData) => connectionHandler.HandleUdpConnection(client, remoteEndPoint, receivedData),
                logger
            );

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                portListener.StopListening();
            };

            await portListener.StartListening();

            Console.WriteLine("Honeypot is running. Press Ctrl+C to stop.");
            Console.ReadLine();
        }

        private static List<int> GetUsedTcpPorts()
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                .Select(endpoint => endpoint.Port)
                .ToList();
        }

        private static List<int> GetUsedUdpPorts()
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()
                .Select(endpoint => endpoint.Port)
                .ToList();
        }
    }
}