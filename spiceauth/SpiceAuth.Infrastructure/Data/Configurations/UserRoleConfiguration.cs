using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Authorization;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
{
    public void Configure(EntityTypeBuilder<UserRole> builder)
    {
        // Composite primary key
        builder.HasKey(ur => new { ur.UserId, ur.RoleId });

        // Indexes
        builder.HasIndex(ur => ur.UserId)
            .HasDatabaseName("IX_UserRoles_UserId");
        
        builder.HasIndex(ur => ur.RoleId)
            .HasDatabaseName("IX_UserRoles_RoleId");
        
        builder.HasIndex(ur => ur.AssignedAt)
            .HasDatabaseName("IX_UserRoles_AssignedAt");
    }
}