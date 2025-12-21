using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.HasKey(rt => rt.Id);
        
        builder.Property(rt => rt.TokenHash)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(rt => rt.Scope)
            .IsRequired()
            .HasMaxLength(500);

        // Indexes
        builder.HasIndex(rt => rt.TokenHash)
            .IsUnique()
            .HasDatabaseName("IX_RefreshTokens_TokenHash");
        
        builder.HasIndex(rt => rt.ExpiresAt)
            .HasDatabaseName("IX_RefreshTokens_ExpiresAt");
        
        builder.HasIndex(rt => new { rt.UserId, rt.ClientId })
            .HasDatabaseName("IX_RefreshTokens_UserId_ClientId");
        
        builder.HasIndex(rt => rt.IsRevoked)
            .HasDatabaseName("IX_RefreshTokens_IsRevoked");

        // Self-referencing relationship for token rotation
        builder.HasOne(rt => rt.ParentToken)
            .WithMany()
            .HasForeignKey(rt => rt.ParentTokenId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}