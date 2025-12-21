using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class OAuthClientConfiguration : IEntityTypeConfiguration<OAuthClient>
{
    public void Configure(EntityTypeBuilder<OAuthClient> builder)
    {
        builder.HasKey(c => c.Id);
        
        builder.Property(c => c.ClientId)
            .IsRequired()
            .HasMaxLength(100);
        
        builder.Property(c => c.ClientSecretHash)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(c => c.Name)
            .IsRequired()
            .HasMaxLength(200);
        
        builder.Property(c => c.Description)
            .HasMaxLength(1000);
        
        builder.Property(c => c.RedirectUris)
            .IsRequired()
            .HasColumnType("jsonb"); // PostgreSQL
        
        builder.Property(c => c.PostLogoutRedirectUris)
            .IsRequired()
            .HasColumnType("jsonb");
        
        builder.Property(c => c.AllowedScopes)
            .IsRequired()
            .HasColumnType("jsonb");
        
        builder.Property(c => c.AllowedGrantTypes)
            .IsRequired()
            .HasColumnType("jsonb");

        // Indexes
        builder.HasIndex(c => c.ClientId)
            .IsUnique()
            .HasDatabaseName("IX_OAuthClients_ClientId");
        
        builder.HasIndex(c => c.IsActive)
            .HasDatabaseName("IX_OAuthClients_IsActive");
        
        builder.HasIndex(c => c.CreatedByUserId)
            .HasDatabaseName("IX_OAuthClients_CreatedByUserId");
        
        builder.HasIndex(c => c.OrganizationId)
            .HasDatabaseName("IX_OAuthClients_OrganizationId");

        // Relationships
        builder.HasMany(c => c.AuthorizationCodes)
            .WithOne(ac => ac.Client)
            .HasForeignKey(ac => ac.ClientId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasMany(c => c.RefreshTokens)
            .WithOne(rt => rt.Client)
            .HasForeignKey(rt => rt.ClientId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasMany(c => c.ConsentGrants)
            .WithOne(cg => cg.Client)
            .HasForeignKey(cg => cg.ClientId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}