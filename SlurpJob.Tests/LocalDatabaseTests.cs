using Microsoft.EntityFrameworkCore;
using SlurpJob.Data;
using SlurpJob.Classification;
using SlurpJob.Models;

namespace SlurpJob.Tests;

/// <summary>
/// Integration tests using the local slurp.db production database copy.
/// These tests validate classifiers against real historical attack data.
/// </summary>
public class LocalDatabaseTests
{
    private const string LocalDbPath = "../../../../slurp.db";
    
    [Fact]
    public async Task LocalDatabase_ShouldExist()
    {
        // Verify the local database copy exists
        Assert.True(File.Exists(LocalDbPath), 
            "Local database not found. Copy slurp.db from production to workspace root.");
    }
    
    [Fact]
    public async Task LocalDatabase_ShouldHaveIncidents()
    {
        // Skip if database doesn't exist (CI/CD environments may not have it)
        if (!File.Exists(LocalDbPath))
        {
            // Skip test
            return;
        }
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        using var db = new SlurpContext(options);
        
        var count = await db.IncidentLogs.CountAsync();
        Assert.True(count > 0, "Local database should contain attack incidents.");
    }
    
    [Fact]
    public async Task HTTPClassifier_ShouldMatchRealHTTPTraffic()
    {
        // Skip if database doesn't exist
        if (!File.Exists(LocalDbPath))
        {
            return;
        }
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        var classifier = new HTTPClassifier();
        
        using var db = new SlurpContext(options);
        
        // Get some incidents classified as HTTP Request
        var httpIncidents = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "HTTP Request")
            .Take(10)
            .ToListAsync();
            
        Assert.NotEmpty(httpIncidents);
        
        // Verify the classifier still identifies these correctly
        foreach (var incident in httpIncidents)
        {
            var result = classifier.Classify(
                incident.Evidence!.PayloadBlob, 
                incident.Protocol, 
                incident.TargetPort
            );
            
            Assert.Equal("HTTP Request", result.Name);
            Assert.Equal(PayloadProtocol.HTTP, result.Protocol);
        }
    }
    
    [Fact]
    public async Task AnalyzeUnclassified_SamplePayloads()
    {
        // Skip if database doesn't exist
        if (!File.Exists(LocalDbPath))
        {
            return;
        }
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        using var db = new SlurpContext(options);
        
        // Get sample unclassified incidents for analysis
        var unclassified = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "Unclassified")
            .Take(100)
            .ToListAsync();
            
        Assert.NotEmpty(unclassified);
        
        // This test documents what kinds of payloads are unclassified
        // Useful for identifying patterns and building new classifiers
        var portDistribution = unclassified
            .GroupBy(i => i.TargetPort)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .Select(g => new { Port = g.Key, Count = g.Count() })
            .ToList();
            
        // Log for manual inspection (this is just for documentation/analysis)
        Assert.NotNull(portDistribution);
    }
}
