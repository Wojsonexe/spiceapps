using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Organization;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class OrganizationMemberConfiguration : IEntityTypeConfiguration<OrganizationMember>
{
    public void Configure(EntityTypeBuilder<OrganizationMember> builder)
    {
        builder.HasKey(om => om.Id);

        // Unique constraint: user can be member only once per organization
        builder.HasIndex(om => new { om.OrganizationId, om.UserId })
            .IsUnique()
            .HasDatabaseName("IX_OrganizationMembers_OrganizationId_UserId");
        
        builder.HasIndex(om => om.UserId)
            .HasDatabaseName("IX_OrganizationMembers_UserId");
        
        builder.HasIndex(om => om.OrganizationId)
            .HasDatabaseName("IX_OrganizationMembers_OrganizationId");
        
        builder.HasIndex(om => om.Role)
            .HasDatabaseName("IX_OrganizationMembers_Role");
        
        builder.HasIndex(om => om.IsActive)
            .HasDatabaseName("IX_OrganizationMembers_IsActive");
    }
}