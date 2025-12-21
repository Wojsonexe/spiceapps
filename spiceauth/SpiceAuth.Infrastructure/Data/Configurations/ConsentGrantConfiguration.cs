using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class ConsentGrantConfiguration : IEntityTypeConfiguration<ConsentGrant>
{
    public void Configure(EntityTypeBuilder<ConsentGrant> builder)
    {
        builder.HasKey(cg => cg.Id);
        
        builder.Property(cg => cg.Scope)
            .IsRequired()
            .HasMaxLength(500);

        // Indexes
        builder.HasIndex(cg => new { cg.UserId, cg.ClientId })
            .IsUnique()
            .HasDatabaseName("IX_ConsentGrants_UserId_ClientId");
        
        builder.HasIndex(cg => cg.IsRevoked)
            .HasDatabaseName("IX_ConsentGrants_IsRevoked");
        
        builder.HasIndex(cg => cg.ExpiresAt)
            .HasDatabaseName("IX_ConsentGrants_ExpiresAt");
    }
}