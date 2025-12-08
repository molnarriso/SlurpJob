using SlurpJob.Models;
using SlurpJob.Services;

namespace SlurpJob.Tests;

public class MemoryStoreTests
{
    [Fact]
    public void AddEvent_ShouldAddToLiveFeed()
    {
        var store = new MemoryStore();
        var evt = new LiveEvent
        {
            Timestamp = DateTime.UtcNow,
            SourceCountry = "US",
            TargetPort = 80,
            Protocol = "TCP"
        };
        
        store.AddEvent(evt, "hash1", new byte[0], null);
        
        var feed = store.GetLiveFeed();
        Assert.Single(feed);
        Assert.Equal("US", feed.First().SourceCountry);
    }

    [Fact]
    public void AddEvent_ShouldCreateDossier()
    {
        var store = new MemoryStore();
        var evt = new LiveEvent { Timestamp = DateTime.UtcNow };
        
        store.AddEvent(evt, "hash1", new byte[] { 1, 2, 3 }, null);
        
        var dossiers = store.GetDossiers();
        Assert.Single(dossiers);
        var dossier = dossiers.First();
        Assert.Equal("hash1", dossier.PayloadHash);
        Assert.Single(dossier.Engagements);
    }

    [Fact]
    public void AddEvent_ShouldGroupEngagements()
    {
        var store = new MemoryStore();
        var evt1 = new LiveEvent { Timestamp = DateTime.UtcNow };
        
        store.AddEvent(evt1, "hash1", new byte[] { 1 }, null);
        store.AddEvent(evt1, "hash1", new byte[] { 1 }, null);
        
        var dossier = store.GetDossiers().First();
        Assert.Single(dossier.Engagements);
        Assert.Equal(2, dossier.Engagements.First().TotalCount);
    }
}
