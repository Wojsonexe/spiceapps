using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class ExternalIdentityConfiguration : IEntityTypeConfiguration<ExternalIdentity>
{
    public void Configure(EntityTypeBuilder<ExternalIdentity> builder)
    {
        builder.HasKey(e => e.Id);
        
        builder.Property(e => e.Provider)
            .IsRequired()
            .HasMaxLength(50);
        
        builder.Property(e => e.ProviderUserId)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(e => e.ProviderUsername)
            .HasMaxLength(100);
        
        builder.Property(e => e.ProviderEmail)
            .HasMaxLength(255);

        // Unique constraint: one external account can be linked to only one user
        builder.HasIndex(e => new { e.Provider, e.ProviderUserId })
            .IsUnique()
            .HasDatabaseName("IX_ExternalIdentities_Provider_ProviderUserId");
        
        builder.HasIndex(e => e.UserId)
            .HasDatabaseName("IX_ExternalIdentities_UserId");
    }
}