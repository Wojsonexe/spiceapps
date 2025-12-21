using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.HasKey(al => al.Id);
        
        builder.Property(al => al.ResourceType)
            .HasMaxLength(100);
        
        builder.Property(al => al.ResourceId)
            .HasMaxLength(100);
        
        builder.Property(al => al.IpAddress)
            .HasMaxLength(45); // IPv6
        
        builder.Property(al => al.UserAgent)
            .HasMaxLength(500);
        
        builder.Property(al => al.FailureReason)
            .HasMaxLength(1000);
        
        builder.Property(al => al.Metadata)
            .HasColumnType("jsonb"); // PostgreSQL

        // Indexes - CRITICAL for audit log performance
        builder.HasIndex(al => al.Timestamp)
            .HasDatabaseName("IX_AuditLogs_Timestamp");
        
        builder.HasIndex(al => al.UserId)
            .HasDatabaseName("IX_AuditLogs_UserId");
        
        builder.HasIndex(al => al.Action)
            .HasDatabaseName("IX_AuditLogs_Action");
        
        builder.HasIndex(al => al.ClientId)
            .HasDatabaseName("IX_AuditLogs_ClientId");
        
        builder.HasIndex(al => al.OrganizationId)
            .HasDatabaseName("IX_AuditLogs_OrganizationId");
        
        builder.HasIndex(al => al.Success)
            .HasDatabaseName("IX_AuditLogs_Success");
        
        // Composite index for common queries
        builder.HasIndex(al => new { al.UserId, al.Timestamp })
            .HasDatabaseName("IX_AuditLogs_UserId_Timestamp");
        
        builder.HasIndex(al => new { al.Action, al.Timestamp })
            .HasDatabaseName("IX_AuditLogs_Action_Timestamp");
    }
}