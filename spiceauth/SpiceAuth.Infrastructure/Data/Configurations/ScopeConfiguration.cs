using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class ScopeConfiguration : IEntityTypeConfiguration<Scope>
{
    public void Configure(EntityTypeBuilder<Scope> builder)
    {
        builder.ToTable("scopes");
        builder.HasKey(s => s.Id);
        
        builder.Property(s => s.Name).IsRequired().HasMaxLength(100);
        builder.Property(s => s.Description).HasMaxLength(500);
        builder.Property(s => s.ResourceServer).IsRequired().HasMaxLength(50);
        
        builder.HasIndex(s => s.Name).IsUnique().HasDatabaseName("ix_scopes_name");
        builder.HasIndex(s => s.ResourceServer).HasDatabaseName("ix_scopes_resource_server");
    }
}