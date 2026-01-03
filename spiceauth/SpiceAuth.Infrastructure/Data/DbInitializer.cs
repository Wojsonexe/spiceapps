using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.Authorization;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Enums;


namespace SpiceAuth.Infrastructure.Data;

public static class DbInitializer
{
    public static async Task SeedAsync(
        ApplicationDbContext context,
        IPasswordHasher passwordHasher)
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
        
        const string superUserEmail = "superuser@local.test";
        const string superUserUsername = "superuser";

        var superUser = await context.Users
            .Include(u => u.UserRoles)
            .FirstOrDefaultAsync(u => u.Email == superUserEmail);

        if (superUser == null)
        {
            superUser = new User
            {
                Id = Guid.NewGuid(),
                Email = superUserEmail,
                Username = superUserUsername,
                FirstName = "Super",
                LastName = "User",
                EmailConfirmed = true,
                IsActive = true,
                IsSuspended = false
            };

            superUser.PasswordHash =
                passwordHasher.HashPassword("SuperUser123!");

            await context.Users.AddAsync(superUser);
            await context.SaveChangesAsync();
        }
        var systemRoles = await context.Roles.ToListAsync();

        foreach (var role in systemRoles)
        {
            var hasRole = await context.UserRoles.AnyAsync(ur =>
                ur.UserId == superUser.Id &&
                ur.RoleId == role.Id);

            if (!hasRole)
            {
                context.UserRoles.Add(new UserRole
                {
                    UserId = superUser.Id,
                    RoleId = role.Id
                });
            }
        }

        if (!await context.Set<OAuthClient>().AnyAsync())
        {
            var testUser = await context.Set<User>().FirstOrDefaultAsync();
            if (testUser == null)
            {
                testUser = new User
                {
                    Id = Guid.NewGuid(),
                    Email = "test@example.com",
                    Username = "testuser",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("Test123!"),
                    FirstName = "Test",
                    LastName = "User",
                    EmailConfirmed = true,
                    IsActive = true,
                    IsSuspended = false,
                    CreatedAt = DateTime.UtcNow
                };
                context.Set<User>().Add(testUser);
                await context.SaveChangesAsync(); // Save to get ID
            }
            
            var testClient = new OAuthClient
            {
                Id = Guid.NewGuid(),
                ClientId = "test-client",
                ClientSecretHash = Convert.ToBase64String(
                    System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes("test-secret"))),
                Name = "Test Application",
                Description = "Test OAuth 2.1 Client for development",
                ClientType = OAuthClientType.Web,
                RedirectUris = System.Text.Json.JsonSerializer.Serialize(new[]
                {
                    "http://localhost:3000/callback",
                    "http://localhost:5173/callback",
                    "https://oauth.pstmn.io/v1/callback" // Postman
                }),
                PostLogoutRedirectUris = System.Text.Json.JsonSerializer.Serialize(new[]
                {
                    "http://localhost:3000",
                    "http://localhost:5173"
                }),
                AllowedScopes = System.Text.Json.JsonSerializer.Serialize(new[]
                {
                    "openid",
                    "profile",
                    "email",
                    "offline_access",
                    "read:posts",
                    "write:posts"
                }),
                AllowedGrantTypes = System.Text.Json.JsonSerializer.Serialize(new[]
                {
                    "authorization_code",
                    "refresh_token"
                }),
                RequireConsent = true,
                RequirePkce = true,
                AccessTokenLifetime = 900,
                RefreshTokenLifetime = 604800,
                IsActive = true,
                CreatedByUserId = testUser.Id,
                CreatedAt = DateTime.UtcNow
            };
            context.Set<OAuthClient>().Add(testClient);
        }
        
        

        await context.SaveChangesAsync();
    }
}