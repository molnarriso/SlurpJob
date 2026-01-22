using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using SlurpJob.Classification;
using SlurpJob.Data;
using SlurpJob.Models;
using SlurpJob.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.SignalR;
using SlurpJob.Hubs;

namespace SlurpJob.Tests;

public class ReclassificationTests
{
    [Fact]
    public async Task ReclassifyUnclassifiedAsync_UpdatesUnclassifiedIncidents()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddDbContextFactory<SlurpContext>(options => options.UseInMemoryDatabase("TestDb_" + Guid.NewGuid()));
        var serviceProvider = services.BuildServiceProvider();
        var factory = serviceProvider.GetRequiredService<IDbContextFactory<SlurpContext>>();

        using (var db = factory.CreateDbContext())
        {
            var incident = new IncidentLog
            {
                Timestamp = DateTime.UtcNow,
                SourceIp = "1.2.3.4",
                CountryCode = "US",
                TargetPort = 80,
                Protocol = "TCP",
                ClassifierName = "Unclassified",
                Evidence = new EvidenceLocker
                {
                    PayloadBlob = System.Text.Encoding.UTF8.GetBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                }
            };
            db.IncidentLogs.Add(incident);
            await db.SaveChangesAsync();
        }

        var mockClassifier = new Mock<IInboundClassifier>();
        mockClassifier.Setup(c => c.Name).Returns("MockHTTP");
        mockClassifier.Setup(c => c.Classify(It.IsAny<byte[]>(), It.IsAny<string>(), It.IsAny<int>()))
                      .Returns(new ClassificationResult { Name = "MockHTTP", Protocol = PayloadProtocol.HTTP, Intent = Intent.Recon });

        var mockHubContext = new Mock<IHubContext<DashboardHub>>();
        var mockLogger = new Mock<ILogger<IngestionService>>();
        var scopeFactory = serviceProvider.GetRequiredService<IServiceScopeFactory>();

        var ingestionService = new IngestionService(
            scopeFactory,
            mockHubContext.Object,
            new[] { mockClassifier.Object },
            mockLogger.Object
        );

        // Act
        // We need to use reflection or make the method internal/protected to call it easily, 
        // but for now let's just use reflection since it's private.
        var method = typeof(IngestionService).GetMethod("ReclassifyUnclassifiedAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
        var task = (Task)method.Invoke(ingestionService, new object[] { CancellationToken.None });
        await task;

        // Assert
        using (var db = factory.CreateDbContext())
        {
            var updatedIncident = await db.IncidentLogs.FirstAsync();
            Assert.Equal("MockHTTP", updatedIncident.ClassifierName);
            Assert.Equal("HTTP", updatedIncident.PayloadProtocol);
            Assert.Equal("Recon", updatedIncident.Intent);
        }
    }
}
