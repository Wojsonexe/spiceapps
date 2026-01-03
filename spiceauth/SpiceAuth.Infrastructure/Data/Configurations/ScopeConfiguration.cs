using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Authorization;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class ScopeConfiguration : IEntityTypeConfiguration<Scope>
{
    public void Configure(EntityTypeBuilder<Scope> builder)
    {
        builder.HasKey(s => s.Id);
        
        builder.Property(s => s.Name)
            .IsRequired()
            .HasMaxLength(100);
        
        builder.Property(s => s.DisplayName)
            .IsRequired()
            .HasMaxLength(200);
        
        builder.Property(s => s.Description)
            .HasMaxLength(500);
        
        builder.Property(s => s.Category)
            .IsRequired()
            .HasMaxLength(50);

        // Indexes
        builder.HasIndex(s => s.Name)
            .IsUnique()
            .HasDatabaseName("IX_Scopes_Name");
        
        builder.HasIndex(s => s.Category)
            .HasDatabaseName("IX_Scopes_Category");
        
        builder.HasIndex(s => s.IsSystemScope)
            .HasDatabaseName("IX_Scopes_IsSystemScope");

        // Relationships
        builder.HasMany(s => s.UserScopes)
            .WithOne(us => us.Scope)
            .HasForeignKey(us => us.ScopeId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}