using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.HasKey(u => u.Id);
        
        builder.Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(u => u.Username)
            .IsRequired()
            .HasMaxLength(50);
        
        builder.Property(u => u.FirstName)
            .HasMaxLength(100);
        
        builder.Property(u => u.LastName)
            .HasMaxLength(100);
        
        builder.Property(u => u.PasswordHash)
            .HasMaxLength(255);

        // Indexes
        builder.HasIndex(u => u.Email)
            .IsUnique()
            .HasDatabaseName("IX_Users_Email");
        
        builder.HasIndex(u => u.Username)
            .IsUnique()
            .HasDatabaseName("IX_Users_Username");
        
        builder.HasIndex(u => u.IsActive)
            .HasDatabaseName("IX_Users_IsActive");
        
        builder.HasIndex(u => u.CreatedAt)
            .HasDatabaseName("IX_Users_CreatedAt");

        // Relationships
        builder.HasMany(u => u.ExternalIdentities)
            .WithOne(e => e.User)
            .HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasMany(u => u.UserRoles)
            .WithOne(ur => ur.User)
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasMany(u => u.UserScopes)
            .WithOne(us => us.User)
            .HasForeignKey(us => us.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasMany(u => u.RefreshTokens)
            .WithOne()
            .HasForeignKey(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasMany(u => u.OrganizationMemberships)
            .WithOne(om => om.User)
            .HasForeignKey(om => om.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(u => u.MfaSettings)
            .WithOne(m => m.User)
            .HasForeignKey<MfaSettings>(m => m.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}