using System;
using System.Threading.Tasks;
using InfluxDB.Client;
using InfluxDB.Client.Api.Domain;
using InfluxDB.Client.Core;
using InfluxDB.Client.Writes;
using SlurpyHoneypot;

namespace SlurpyHoneypot
{
    public class InfluxDbLogger : IDisposable
    {
        private readonly InfluxDBClient _influxDbClient;
        private readonly string _bucket;
        private readonly string _org;
        private readonly WriteApiAsync _writeApi;

        public InfluxDbLogger(string connectionString, string bucket, string org)
        {
            _influxDbClient = InfluxDBClientFactory.Create(connectionString);
            _bucket = bucket;
            _org = org;
            _writeApi = _influxDbClient.GetWriteApiAsync();
        }

        public async Task LogEvent(ConnectionDetails connectionDetails, string eventType)
        {
            var point = CreatePoint("event", connectionDetails, eventType);
            await _writeApi.WritePointAsync(point, _org, _bucket);
        }

        public async Task LogError(Exception exception, string message = null)
        {
            var point = PointData.Measurement("errors")
                .Tag("type", "exception")
                .Field("message", exception.Message+ message??"")
                .Field("stack_trace", exception.StackTrace)
                .Timestamp(DateTime.UtcNow, WritePrecision.Ns);

            await _writeApi.WritePointAsync(point, _org, _bucket);
        }

        private PointData CreatePoint(string measurement, ConnectionDetails connectionDetails, string tagValue)
        {
            return PointData.Measurement(measurement)
                .Tag("remote_endpoint", connectionDetails.RemoteEndPoint.ToString())
                .Tag("protocol", connectionDetails.Protocol.ToString())
                .Tag("type", tagValue)
                .Field("data_size", connectionDetails.DataSize)
                .Field("partial_data", connectionDetails.PartialData)
                .Field("data_hash", connectionDetails.DataHash)
                .Timestamp(connectionDetails.Timestamp, WritePrecision.Ns);
        }

        public void Dispose()
        {
            _influxDbClient?.Dispose();
        }
    }

}
