using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Authorization;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class UserScopeConfiguration : IEntityTypeConfiguration<UserScope>
{
    public void Configure(EntityTypeBuilder<UserScope> builder)
    {
        // Composite primary key
        builder.HasKey(us => new { us.UserId, us.ScopeId });

        // Indexes
        builder.HasIndex(us => us.UserId)
            .HasDatabaseName("IX_UserScopes_UserId");
        
        builder.HasIndex(us => us.ScopeId)
            .HasDatabaseName("IX_UserScopes_ScopeId");
        
        builder.HasIndex(us => us.ExpiresAt)
            .HasDatabaseName("IX_UserScopes_ExpiresAt");
        
        builder.HasIndex(us => us.GrantedAt)
            .HasDatabaseName("IX_UserScopes_GrantedAt");
    }
}