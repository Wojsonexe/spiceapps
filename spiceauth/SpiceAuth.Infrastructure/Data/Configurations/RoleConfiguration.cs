using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Authorization;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class RoleConfiguration : IEntityTypeConfiguration<Role>
{
    public void Configure(EntityTypeBuilder<Role> builder)
    {
        builder.HasKey(r => r.Id);
        
        builder.Property(r => r.Name)
            .IsRequired()
            .HasMaxLength(100);
        
        builder.Property(r => r.Description)
            .HasMaxLength(500);
        
        builder.Property(r => r.Permissions)
            .HasColumnType("jsonb"); // PostgreSQL

        // Indexes
        builder.HasIndex(r => r.Name)
            .IsUnique()
            .HasDatabaseName("IX_Roles_Name");
        
        builder.HasIndex(r => r.IsSystemRole)
            .HasDatabaseName("IX_Roles_IsSystemRole");

        // Relationships
        builder.HasMany(r => r.UserRoles)
            .WithOne(ur => ur.Role)
            .HasForeignKey(ur => ur.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}