using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");
        builder.HasKey(t => t.Id);
        
        builder.Property(t => t.Token).IsRequired().HasMaxLength(128);
        builder.Property(t => t.Scope).IsRequired().HasMaxLength(500);
        builder.Property(t => t.RevokedReason).HasMaxLength(200);
        builder.Property(t => t.IpAddress).HasMaxLength(45);
        builder.Property(t => t.UserAgent).HasMaxLength(500);
        
        builder.HasIndex(t => t.Token).IsUnique().HasDatabaseName("ix_refresh_tokens_token");
        builder.HasIndex(t => new { t.IsRevoked, t.ExpiresAt }).HasDatabaseName("ix_refresh_tokens_cleanup");
        builder.HasIndex(t => new { t.UserId, t.ClientId, t.IsRevoked }).HasDatabaseName("ix_refresh_tokens_user_client");
        
        builder.HasOne(t => t.Client)
            .WithMany(c => c.RefreshTokens)
            .HasForeignKey(t => t.ClientId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasOne(t => t.User)
            .WithMany(u => u.RefreshTokens)
            .HasForeignKey(t => t.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}