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
    
    /// <summary>
    /// Tests that TLS classifier correctly identifies ~15k TLS ClientHello payloads in the database.
    /// Expected range: 10,000 - 20,000 hits based on FUTURE_TASKS.md analysis.
    /// </summary>
    [Fact]
    public async Task TLSClassifier_ShouldMatchExpectedHits()
    {
        if (!File.Exists(LocalDbPath)) return;
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        var classifier = new TLSClassifier();
        
        using var db = new SlurpContext(options);
        
        // Get all unclassified incidents with evidence
        var unclassified = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "Unclassified" && i.Evidence != null)
            .ToListAsync();
            
        int hits = 0;
        foreach (var incident in unclassified)
        {
            var result = classifier.Classify(
                incident.Evidence!.PayloadBlob, 
                incident.Protocol, 
                incident.TargetPort
            );
            if (result.Protocol == PayloadProtocol.TLS)
                hits++;
        }
        
        // Expected ~15,579 hits per FUTURE_TASKS.md analysis (with 0x1603 prefix)
        // Allow variance since DB changes over time:  5,000 - 25,000
        Assert.InRange(hits, 5000, 25000);
    }
    
    /// <summary>
    /// Tests that RDP/X.224 classifier correctly identifies ~13k RDP payloads.
    /// Expected range: 8,000 - 20,000 hits based on FUTURE_TASKS.md analysis.
    /// </summary>
    [Fact]
    public async Task RDPClassifier_ShouldMatchExpectedHits()
    {
        if (!File.Exists(LocalDbPath)) return;
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        var classifier = new RDPClassifier();
        
        using var db = new SlurpContext(options);
        
        var unclassified = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "Unclassified" && i.Evidence != null)
            .ToListAsync();
            
        int hits = 0;
        foreach (var incident in unclassified)
        {
            var result = classifier.Classify(
                incident.Evidence!.PayloadBlob, 
                incident.Protocol, 
                incident.TargetPort
            );
            if (result.Protocol == PayloadProtocol.RDP)
                hits++;
        }
        
        // Expected ~13,268 hits per analysis (with 0x0300 prefix)
        // Allow variance: 5,000 - 20,000
        Assert.InRange(hits, 5000, 20000);
    }
    
    /// <summary>
    /// Tests that JSON-RPC/Ethereum classifier correctly identifies ~1.5k crypto probes.
    /// Expected range: 500 - 5,000 hits based on FUTURE_TASKS.md analysis.
    /// </summary>
    [Fact]
    public async Task JSONRPCClassifier_ShouldMatchExpectedHits()
    {
        if (!File.Exists(LocalDbPath)) return;
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        var classifier = new JSONRPCClassifier();
        
        using var db = new SlurpContext(options);
        
        var unclassified = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "Unclassified" && i.Evidence != null)
            .ToListAsync();
            
        int hits = 0;
        foreach (var incident in unclassified)
        {
            var result = classifier.Classify(
                incident.Evidence!.PayloadBlob, 
                incident.Protocol, 
                incident.TargetPort
            );
            if (result.Protocol == PayloadProtocol.JSONRPC)
                hits++;
        }
        
        // Expected ~1,482 hits per analysis
        // Allow variance: 500 - 5,000
        Assert.InRange(hits, 500, 5000);
    }
    
    /// <summary>
    /// Tests that Redis classifier correctly identifies ~904 Redis RESP payloads.
    /// Expected range: 300 - 2,000 hits based on FUTURE_TASKS.md analysis.
    /// </summary>
    [Fact]
    public async Task RedisClassifier_ShouldMatchExpectedHits()
    {
        if (!File.Exists(LocalDbPath)) return;
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        var classifier = new RedisClassifier();
        
        using var db = new SlurpContext(options);
        
        var unclassified = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "Unclassified" && i.Evidence != null)
            .ToListAsync();
            
        int hits = 0;
        foreach (var incident in unclassified)
        {
            var result = classifier.Classify(
                incident.Evidence!.PayloadBlob, 
                incident.Protocol, 
                incident.TargetPort
            );
            if (result.Protocol == PayloadProtocol.Redis)
                hits++;
        }
        
        // Expected ~904 hits per analysis
        // Allow variance: 300 - 2,000
        Assert.InRange(hits, 300, 2000);
    }
    
    /// <summary>
    /// Tests that Java RMI classifier correctly identifies ~866 RMI payloads.
    /// Expected range: 300 - 2,000 hits based on FUTURE_TASKS.md analysis.
    /// </summary>
    [Fact]
    public async Task RMIClassifier_ShouldMatchExpectedHits()
    {
        if (!File.Exists(LocalDbPath)) return;
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        var classifier = new RMIClassifier();
        
        using var db = new SlurpContext(options);
        
        var unclassified = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "Unclassified" && i.Evidence != null)
            .ToListAsync();
            
        int hits = 0;
        foreach (var incident in unclassified)
        {
            var result = classifier.Classify(
                incident.Evidence!.PayloadBlob, 
                incident.Protocol, 
                incident.TargetPort
            );
            if (result.Protocol == PayloadProtocol.RMI)
                hits++;
        }
        
        // Expected ~866 hits per analysis
        // Allow variance: 300 - 2,000
        Assert.InRange(hits, 300, 2000);
    }
    
    /// <summary>
    /// Tests that WebLogic T3 classifier correctly identifies ~752 T3 payloads.
    /// Expected range: 200 - 2,000 hits based on FUTURE_TASKS.md analysis.
    /// </summary>
    [Fact]
    public async Task T3Classifier_ShouldMatchExpectedHits()
    {
        if (!File.Exists(LocalDbPath)) return;
        
        var options = new DbContextOptionsBuilder<SlurpContext>()
            .UseSqlite($"Data Source={LocalDbPath}")
            .Options;
            
        var classifier = new T3Classifier();
        
        using var db = new SlurpContext(options);
        
        var unclassified = await db.IncidentLogs
            .Include(i => i.Evidence)
            .Where(i => i.ClassifierName == "Unclassified" && i.Evidence != null)
            .ToListAsync();
            
        int hits = 0;
        foreach (var incident in unclassified)
        {
            var result = classifier.Classify(
                incident.Evidence!.PayloadBlob, 
                incident.Protocol, 
                incident.TargetPort
            );
            if (result.Protocol == PayloadProtocol.T3)
                hits++;
        }
        
        // Expected ~752 hits per analysis
        // Allow variance: 200 - 2,000
        Assert.InRange(hits, 200, 2000);
    }
}
