using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens");
        
        builder.HasKey(rt => rt.Id);
        
        builder.Property(rt => rt.TokenHash)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(rt => rt.Scope)
            .IsRequired()
            .HasMaxLength(500);

        builder.HasOne<SpiceAuth.Core.Entities.Identity.ApplicationUser>()
            .WithMany()
            .HasForeignKey(rt => rt.UserId)
            .HasConstraintName("FK_RefreshTokens_AspNetUsers_UserId")
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne<OAuthClient>()
            .WithMany()
            .HasForeignKey(rt => rt.ClientId)
            .HasConstraintName("FK_RefreshTokens_OAuthClients_ClientId")
            .OnDelete(DeleteBehavior.Cascade);

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

        builder.HasOne(rt => rt.ParentToken)
            .WithMany()
            .HasForeignKey(rt => rt.ParentTokenId)
            .HasConstraintName("FK_RefreshTokens_RefreshTokens_ParentTokenId")
            .OnDelete(DeleteBehavior.Restrict);
    }
}
