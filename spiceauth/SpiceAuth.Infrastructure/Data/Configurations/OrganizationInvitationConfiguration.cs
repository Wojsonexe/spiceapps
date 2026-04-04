using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Organization;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class OrganizationInvitationConfiguration : IEntityTypeConfiguration<OrganizationInvitation>
{
    public void Configure(EntityTypeBuilder<OrganizationInvitation> builder)
    {
        builder.HasKey(oi => oi.Id);
        
        builder.Property(oi => oi.Email)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(oi => oi.Token)
            .IsRequired()
            .HasMaxLength(255);

        // Indexes
        builder.HasIndex(oi => oi.Token)
            .IsUnique()
            .HasDatabaseName("IX_OrganizationInvitations_Token");
        
        builder.HasIndex(oi => oi.Email)
            .HasDatabaseName("IX_OrganizationInvitations_Email");
        
        builder.HasIndex(oi => oi.OrganizationId)
            .HasDatabaseName("IX_OrganizationInvitations_OrganizationId");
        
        builder.HasIndex(oi => oi.ExpiresAt)
            .HasDatabaseName("IX_OrganizationInvitations_ExpiresAt");
        
        builder.HasIndex(oi => oi.IsRevoked)
            .HasDatabaseName("IX_OrganizationInvitations_IsRevoked");
    }
}