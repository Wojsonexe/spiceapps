using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class OAuthClientConfiguration : IEntityTypeConfiguration<OAuthClient>
{
    public void Configure(EntityTypeBuilder<OAuthClient> builder)
    {
        builder.ToTable("oauth_clients");
        builder.HasKey(c => c.Id);
        
        builder.Property(c => c.ClientId).IsRequired().HasMaxLength(100);
        builder.Property(c => c.ClientSecret).IsRequired().HasMaxLength(128);
        builder.Property(c => c.Name).IsRequired().HasMaxLength(200);
        builder.Property(c => c.Description).HasMaxLength(500);
        builder.Property(c => c.ClientType).IsRequired().HasConversion<int>();
        builder.Property(c => c.RedirectUris).IsRequired().HasColumnType("jsonb");
        builder.Property(c => c.PostLogoutRedirectUris).HasColumnType("jsonb");
        builder.Property(c => c.AllowedScopes).IsRequired().HasColumnType("jsonb");
        builder.Property(c => c.AccessTokenLifetime).IsRequired().HasDefaultValue(900);
        builder.Property(c => c.RefreshTokenLifetime).IsRequired().HasDefaultValue(604800);
        
        builder.HasIndex(c => c.ClientId).IsUnique().HasDatabaseName("ix_oauth_clients_client_id");
        builder.HasIndex(c => c.IsActive).HasDatabaseName("ix_oauth_clients_is_active");
    }
}