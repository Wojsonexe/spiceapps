using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class EmailVerificationTokenConfiguration : IEntityTypeConfiguration<EmailVerificationToken>
{
    public void Configure(EntityTypeBuilder<EmailVerificationToken> builder)
    {
        builder.ToTable("EmailVerificationTokens");
        
        builder.HasKey(e => e.Id);
        
        builder.Property(e => e.Token)
            .IsRequired()
            .HasMaxLength(500);
        
        builder.Property(e => e.Email)
            .IsRequired()
            .HasMaxLength(256);
        
        builder.Property(e => e.IpAddress)
            .HasMaxLength(45);
        
        builder.Property(e => e.UserAgent)
            .HasMaxLength(500);
        
        builder.HasIndex(e => e.Token)
            .IsUnique();
        
        builder.HasIndex(e => e.UserId);
        builder.HasIndex(e => e.ExpiresAt);
        
        builder.HasOne(e => e.User)
            .WithMany()
            .HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}