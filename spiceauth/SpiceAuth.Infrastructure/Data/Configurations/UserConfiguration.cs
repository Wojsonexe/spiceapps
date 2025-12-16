using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("users");
        
        builder.HasKey(u => u.Id);
        
        // Properties
        builder.Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(256);
        
        builder.Property(u => u.NormalizedEmail)
            .IsRequired()
            .HasMaxLength(256);
        
        builder.Property(u => u.Username)
            .IsRequired()
            .HasMaxLength(50);
        
        builder.Property(u => u.PasswordHash)
            .IsRequired()
            .HasMaxLength(512);
        
        builder.Property(u => u.IsActive)
            .IsRequired()
            .HasDefaultValue(true);
        
        builder.Property(u => u.IsLocked)
            .IsRequired()
            .HasDefaultValue(false);
        
        builder.Property(u => u.FailedLoginAttempts)
            .IsRequired()
            .HasDefaultValue(0);
        
        builder.Property(u => u.CreatedAt)
            .IsRequired();
        
        builder.Property(u => u.UpdatedAt)
            .IsRequired();
        
        // Indexes
        builder.HasIndex(u => u.NormalizedEmail)
            .IsUnique()
            .HasDatabaseName("ix_users_normalized_email");
        
        builder.HasIndex(u => u.Username)
            .IsUnique()
            .HasDatabaseName("ix_users_username");
        
        builder.HasIndex(u => u.IsActive)
            .HasDatabaseName("ix_users_is_active");
        
        builder.HasIndex(u => u.LastLoginAt)
            .HasDatabaseName("ix_users_last_login_at");
        
        // Relationships
        builder.HasOne(u => u.DiscordAccount)
            .WithOne(d => d.User)
            .HasForeignKey<DiscordAccount>(d => d.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}