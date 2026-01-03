using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class LoginAttemptConfiguration : IEntityTypeConfiguration<LoginAttempt>
{
    public void Configure(EntityTypeBuilder<LoginAttempt> builder)
    {
        builder.ToTable("LoginAttempts");
        
        builder.HasKey(e => e.Id);
        
        builder.Property(e => e.Email)
            .IsRequired()
            .HasMaxLength(256);
        
        builder.Property(e => e.IpAddress)
            .IsRequired()
            .HasMaxLength(45);
        
        builder.Property(e => e.UserAgent)
            .HasMaxLength(500);
        
        builder.Property(e => e.FailureReason)
            .HasMaxLength(500);
        
        builder.HasIndex(e => e.Email);
        builder.HasIndex(e => e.IpAddress);
        builder.HasIndex(e => e.AttemptedAt);
        builder.HasIndex(e => new { e.Email, e.AttemptedAt });
        
        builder.HasOne(e => e.User)
            .WithMany()
            .HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.SetNull);
    }
}