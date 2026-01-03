using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class SecurityEventConfiguration : IEntityTypeConfiguration<SecurityEvent>
{
    public void Configure(EntityTypeBuilder<SecurityEvent> builder)
    {
        builder.HasKey(se => se.Id);
        
        builder.Property(se => se.Description)
            .IsRequired()
            .HasMaxLength(1000);
        
        builder.Property(se => se.IpAddress)
            .HasMaxLength(45); // IPv6

        // Indexes
        builder.HasIndex(se => se.UserId)
            .HasDatabaseName("IX_SecurityEvents_UserId");
        
        builder.HasIndex(se => se.Timestamp)
            .HasDatabaseName("IX_SecurityEvents_Timestamp");
        
        builder.HasIndex(se => se.EventType)
            .HasDatabaseName("IX_SecurityEvents_EventType");
        
        builder.HasIndex(se => se.Severity)
            .HasDatabaseName("IX_SecurityEvents_Severity");
        
        builder.HasIndex(se => se.Resolved)
            .HasDatabaseName("IX_SecurityEvents_Resolved");
        
        // Composite index for unresolved high-severity events
        builder.HasIndex(se => new { se.Resolved, se.Severity, se.Timestamp })
            .HasDatabaseName("IX_SecurityEvents_Resolved_Severity_Timestamp");
    }
}