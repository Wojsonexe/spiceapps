using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class OAuthAuthorizationCodeConfiguration : IEntityTypeConfiguration<OAuthAuthorizationCode>
{
    public void Configure(EntityTypeBuilder<OAuthAuthorizationCode> builder)
    {
        builder.ToTable("oauth_authorization_codes");
        builder.HasKey(c => c.Id);
        
        builder.Property(c => c.Code).IsRequired().HasMaxLength(128);
        builder.Property(c => c.RedirectUri).IsRequired().HasMaxLength(500);
        builder.Property(c => c.Scope).IsRequired().HasMaxLength(500);
        builder.Property(c => c.Nonce).HasMaxLength(128);
        builder.Property(c => c.CodeChallenge).HasMaxLength(128);
        builder.Property(c => c.CodeChallengeMethod).HasConversion<int>();
        
        builder.HasIndex(c => c.Code).IsUnique().HasDatabaseName("ix_oauth_authorization_codes_code");
        builder.HasIndex(c => c.ExpiresAt).HasDatabaseName("ix_oauth_authorization_codes_expires_at");
        builder.HasIndex(c => new { c.IsUsed, c.ExpiresAt }).HasDatabaseName("ix_oauth_authorization_codes_cleanup");
        
        builder.HasOne(c => c.Client)
            .WithMany(cl => cl.AuthorizationCodes)
            .HasForeignKey(c => c.ClientId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasOne(c => c.User)
            .WithMany(u => u.AuthorizationCodes)
            .HasForeignKey(c => c.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
