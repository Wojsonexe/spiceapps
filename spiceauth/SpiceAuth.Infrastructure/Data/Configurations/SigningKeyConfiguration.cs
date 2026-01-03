using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class SigningKeyConfiguration : IEntityTypeConfiguration<SigningKey>
{
    public void Configure(EntityTypeBuilder<SigningKey> builder)
    {
        builder.HasKey(sk => sk.Id);
        
        builder.Property(sk => sk.KeyId)
            .IsRequired()
            .HasMaxLength(100);
        
        builder.Property(sk => sk.Algorithm)
            .IsRequired()
            .HasMaxLength(20);
        
        builder.Property(sk => sk.PublicKey)
            .IsRequired()
            .HasColumnType("text");
        
        builder.Property(sk => sk.PrivateKey)
            .IsRequired()
            .HasColumnType("text");

        // Indexes
        builder.HasIndex(sk => sk.KeyId)
            .IsUnique()
            .HasDatabaseName("IX_SigningKeys_KeyId");
        
        builder.HasIndex(sk => sk.IsActive)
            .HasDatabaseName("IX_SigningKeys_IsActive");
        
        builder.HasIndex(sk => sk.ExpiresAt)
            .HasDatabaseName("IX_SigningKeys_ExpiresAt");
    }
}