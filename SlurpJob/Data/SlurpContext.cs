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
            
        // One-to-One relationship
        modelBuilder.Entity<IncidentLog>()
            .HasOne(i => i.Evidence)
            .WithOne(e => e.Incident)
            .HasForeignKey<EvidenceLocker>(e => e.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
