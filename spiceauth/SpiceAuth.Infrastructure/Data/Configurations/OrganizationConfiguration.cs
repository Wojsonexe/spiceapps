using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Organization;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class OrganizationConfiguration : IEntityTypeConfiguration<Organization>
{
    public void Configure(EntityTypeBuilder<Organization> builder)
    {
        builder.HasKey(o => o.Id);
        
        builder.Property(o => o.Name)
            .IsRequired()
            .HasMaxLength(200);
        
        builder.Property(o => o.Slug)
            .IsRequired()
            .HasMaxLength(100);
        
        builder.Property(o => o.Description)
            .HasMaxLength(1000);
        
        builder.Property(o => o.LogoUrl)
            .HasMaxLength(500);
        
        builder.Property(o => o.Settings)
            .HasColumnType("jsonb"); // PostgreSQL

        // Indexes
        builder.HasIndex(o => o.Name)
            .IsUnique()
            .HasDatabaseName("IX_Organizations_Name");
        
        builder.HasIndex(o => o.Slug)
            .IsUnique()
            .HasDatabaseName("IX_Organizations_Slug");
        
        builder.HasIndex(o => o.OwnerId)
            .HasDatabaseName("IX_Organizations_OwnerId");
        
        builder.HasIndex(o => o.IsActive)
            .HasDatabaseName("IX_Organizations_IsActive");

        // Relationships
        builder.HasOne(o => o.Owner)
            .WithMany()
            .HasForeignKey(o => o.OwnerId)
            .OnDelete(DeleteBehavior.Restrict);
        
        builder.HasMany(o => o.Members)
            .WithOne(om => om.Organization)
            .HasForeignKey(om => om.OrganizationId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasMany(o => o.Invitations)
            .WithOne(oi => oi.Organization)
            .HasForeignKey(oi => oi.OrganizationId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}