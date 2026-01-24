using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Moq;
using SlurpJob.Services;
using Xunit;

namespace SlurpJob.Tests;

public class PortTableServiceTests
{
    [Fact]
    public void GetPortDescription_ShouldReturnCorrectDescriptions()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<PortTableService>>();
        var mockEnv = new Mock<IHostEnvironment>();
        
        // Note: In tests, the CSV might need to be present in the output directory
        // The service looks in AppDomain.CurrentDomain.BaseDirectory
        var service = new PortTableService(mockLogger.Object, mockEnv.Object);

        // Act & Assert
        // Port 22: SSH (TCP/UDP)
        var sshTcp = service.GetPortDescription(22, "TCP");
        Assert.NotNull(sshTcp.Short);
        Assert.Contains("SSH", sshTcp.Short);

        var sshUdp = service.GetPortDescription(22, "UDP");
        Assert.NotNull(sshUdp.Short);
        Assert.Contains("SSH", sshUdp.Short);

        // Port 80: HTTP (TCP only in CSV usually, v3 is UDP but CSV might be specific)
        var httpTcp = service.GetPortDescription(80, "TCP");
        Assert.NotNull(httpTcp.Short);
        Assert.Contains("HTTP", httpTcp.Short);

        // Port 319: PTP Event (UDP only)
        var ptpUdp = service.GetPortDescription(319, "UDP");
        Assert.NotNull(ptpUdp.Short);
        Assert.Contains("PTP", ptpUdp.Short);

        var ptpTcp = service.GetPortDescription(319, "TCP");
        Assert.Null(ptpTcp.Short);

        // Invalid Port
        var invalid = service.GetPortDescription(99999, "TCP");
        Assert.Null(invalid.Short);
    }
}
