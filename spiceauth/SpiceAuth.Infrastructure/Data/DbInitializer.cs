using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.Authorization;

namespace SpiceAuth.Infrastructure.Data;

public static class DbInitializer
{
    public static async Task SeedAsync(ApplicationDbContext context)
    {
        // Ensure database is created
        await context.Database.EnsureCreatedAsync();

        // Seed Roles
        if (!await context.Roles.AnyAsync())
        {
            var roles = new[]
            {
                new Role
                {
                    Id = Guid.NewGuid(),
                    Name = "Admin",
                    Description = "System administrator with full access",
                    IsSystemRole = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    Id = Guid.NewGuid(),
                    Name = "User",
                    Description = "Standard user",
                    IsSystemRole = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    Id = Guid.NewGuid(),
                    Name = "Moderator",
                    Description = "Content moderator",
                    IsSystemRole = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Role
                {
                    Id = Guid.NewGuid(),
                    Name = "Developer",
                    Description = "Application developer with OAuth client management",
                    IsSystemRole = true,
                    CreatedAt = DateTime.UtcNow
                }
            };
            await context.Roles.AddRangeAsync(roles);
        }

        // Seed Scopes (OIDC + Custom)
        if (!await context.Scopes.AnyAsync())
        {
            var scopes = new[]
            {
                // OIDC Standard Scopes
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "openid",
                    DisplayName = "OpenID",
                    Description = "Required for OIDC authentication",
                    Category = "OIDC",
                    IsSystemScope = true,
                    RequiresConsent = false,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "profile",
                    DisplayName = "Profile Information",
                    Description = "Access to basic profile information (name, username, picture)",
                    Category = "Profile",
                    IsSystemScope = true,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "email",
                    DisplayName = "Email Address",
                    Description = "Access to email address",
                    Category = "Profile",
                    IsSystemScope = true,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "offline_access",
                    DisplayName = "Offline Access",
                    Description = "Access to refresh tokens for long-lived sessions",
                    Category = "OIDC",
                    IsSystemScope = true,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                
                // Custom Application Scopes
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "read:posts",
                    DisplayName = "Read Posts",
                    Description = "Read access to posts",
                    Category = "Content",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "write:posts",
                    DisplayName = "Write Posts",
                    Description = "Create and edit posts",
                    Category = "Content",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "delete:posts",
                    DisplayName = "Delete Posts",
                    Description = "Delete posts",
                    Category = "Content",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "admin:users",
                    DisplayName = "User Administration",
                    Description = "Full user management capabilities",
                    Category = "Admin",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "admin:roles",
                    DisplayName = "Role Administration",
                    Description = "Manage roles and permissions",
                    Category = "Admin",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "org:read",
                    DisplayName = "Read Organization",
                    Description = "Read organization information",
                    Category = "Organization",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "org:write",
                    DisplayName = "Write Organization",
                    Description = "Update organization settings",
                    Category = "Organization",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                },
                new Scope
                {
                    Id = Guid.NewGuid(),
                    Name = "org:manage",
                    DisplayName = "Manage Organization",
                    Description = "Full organization management including members",
                    Category = "Organization",
                    IsSystemScope = false,
                    RequiresConsent = true,
                    CreatedAt = DateTime.UtcNow
                }
            };
            await context.Scopes.AddRangeAsync(scopes);
        }

        await context.SaveChangesAsync();
    }
}