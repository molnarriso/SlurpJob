using Microsoft.EntityFrameworkCore;
using SlurpJob.Models;

namespace SlurpJob.Data;

public class SlurpContext : DbContext
{
    public DbSet<IncidentLog> IncidentLogs { get; set; }
    public DbSet<EvidenceLocker> EvidenceLockers { get; set; }

    public SlurpContext(DbContextOptions<SlurpContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => i.Timestamp);

        // Filtering Indexes
        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => i.CountryCode);

        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => i.ClassifierName);
        
        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => i.AttackId);

        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => i.TargetPort);

        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => i.Intent);
        
        // Composite indexes for common query patterns (Time + Filter)
        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => new { i.Timestamp, i.CountryCode });
        
        modelBuilder.Entity<IncidentLog>()
            .HasIndex(i => new { i.Timestamp, i.ClassifierName });
            
        // One-to-One relationship
        modelBuilder.Entity<IncidentLog>()
            .HasOne(i => i.Evidence)
            .WithOne(e => e.Incident)
            .HasForeignKey<EvidenceLocker>(e => e.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
