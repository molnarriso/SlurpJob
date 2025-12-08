using Microsoft.EntityFrameworkCore;

namespace SlurpJob.Data;

public class SlurpContext : DbContext
{
    public DbSet<Signature> Signatures { get; set; }
    public DbSet<ActivityLog> ActivityLogs { get; set; }
    public DbSet<GeoStat> GeoStats { get; set; }

    public SlurpContext(DbContextOptions<SlurpContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Signature>()
            .HasKey(s => s.Hash);
            
        modelBuilder.Entity<GeoStat>()
            .HasKey(g => new { g.Date, g.CountryCode });
    }
}

public class Signature
{
    public string Hash { get; set; } = string.Empty;
    public byte[] PayloadRaw { get; set; } = Array.Empty<byte>();
    public string? SniHostname { get; set; }
    public DateTime FirstSeen { get; set; }
}

public class ActivityLog
{
    public int Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string SignatureHash { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public int TargetPort { get; set; }
    public int Count { get; set; }
    public long TotalBytes { get; set; }
}

public class GeoStat
{
    public DateTime Date { get; set; } // Just the Date part
    public string CountryCode { get; set; } = string.Empty;
    public long TotalHits { get; set; }
}
