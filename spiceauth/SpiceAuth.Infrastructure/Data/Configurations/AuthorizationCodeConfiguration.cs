using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class AuthorizationCodeConfiguration : IEntityTypeConfiguration<AuthorizationCode>
{
    public void Configure(EntityTypeBuilder<AuthorizationCode> builder)
    {
        builder.HasKey(ac => ac.Id);
        
        builder.Property(ac => ac.Code)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(ac => ac.RedirectUri)
            .IsRequired()
            .HasMaxLength(500);
        
        builder.Property(ac => ac.Scope)
            .IsRequired()
            .HasMaxLength(500);
        
        builder.Property(ac => ac.CodeChallenge)
            .HasMaxLength(255);
        
        builder.Property(ac => ac.CodeChallengeMethod)
            .HasMaxLength(10);
        
        builder.Property(ac => ac.Nonce)
            .HasMaxLength(255);

        // Indexes
        builder.HasIndex(ac => ac.Code)
            .IsUnique()
            .HasDatabaseName("IX_AuthorizationCodes_Code");
        
        builder.HasIndex(ac => ac.ExpiresAt)
            .HasDatabaseName("IX_AuthorizationCodes_ExpiresAt");
        
        builder.HasIndex(ac => new { ac.ClientId, ac.UserId })
            .HasDatabaseName("IX_AuthorizationCodes_ClientId_UserId");
    }
}