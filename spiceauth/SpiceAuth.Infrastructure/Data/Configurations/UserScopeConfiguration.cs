using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class UserScopeConfiguration : IEntityTypeConfiguration<UserScope>
{
    public void Configure(EntityTypeBuilder<UserScope> builder)
    {
        builder.ToTable("user_scopes");
        builder.HasKey(us => new { us.UserId, us.ScopeId });
        
        builder.HasOne(us => us.User)
            .WithMany(u => u.UserScopes)
            .HasForeignKey(us => us.UserId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasOne(us => us.Scope)
            .WithMany(s => s.UserScopes)
            .HasForeignKey(us => us.ScopeId)
            .OnDelete(DeleteBehavior.Cascade);
        
        builder.HasOne(us => us.GrantedBy)
            .WithMany()
            .HasForeignKey(us => us.GrantedByUserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}