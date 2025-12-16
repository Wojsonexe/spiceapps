using Microsoft.EntityFrameworkCore;
using SpiceAuth.Domain.Entities;
using SpiceAuth.Domain.Enums;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SpiceAuth.Infrastructure.Data;

public static class SpiceAuthDbContextSeed
{
    public static async Task SeedAsync(SpiceAuthDbContext context)
    {
        await SeedRolesAsync(context);
        await SeedScopesAsync(context);
        await SeedOAuthClientsAsync(context);
    }
    
    private static async Task SeedRolesAsync(SpiceAuthDbContext context)
    {
        if (await context.Roles.AnyAsync())
            return;
        
        var roles = new[]
        {
            new Role
            {
                Id = Guid.Parse("00000000-0000-0000-0000-000000000001"),
                Name = "SuperAdmin",
                Description = "Full system access - cannot be deleted",
                IsSystemRole = true,
                CreatedAt = DateTime.UtcNow
            },
            new Role
            {
                Id = Guid.Parse("00000000-0000-0000-0000-000000000002"),
                Name = "Admin",
                Description = "Administrative access - can approve registrations and manage users",
                IsSystemRole = true,
                CreatedAt = DateTime.UtcNow
            },
            new Role
            {
                Id = Guid.Parse("00000000-0000-0000-0000-000000000003"),
                Name = "User",
                Description = "Standard user role",
                IsSystemRole = true,
                CreatedAt = DateTime.UtcNow
            }
        };
        
        await context.Roles.AddRangeAsync(roles);
        await context.SaveChangesAsync();
    }
    
    private static async Task SeedScopesAsync(SpiceAuthDbContext context)
    {
        if (await context.Scopes.AnyAsync())
            return;
        
        var scopes = new[]
        {
            // OIDC Standard Scopes
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "openid",
                Description = "OpenID Connect authentication",
                ResourceServer = "all",
                CreatedAt = DateTime.UtcNow
            },
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "profile",
                Description = "User profile information (username, etc.)",
                ResourceServer = "all",
                CreatedAt = DateTime.UtcNow
            },
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "email",
                Description = "User email address",
                ResourceServer = "all",
                CreatedAt = DateTime.UtcNow
            },
            
            // SpiceAuth Scopes
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "user:read",
                Description = "Read own user data",
                ResourceServer = "spiceauth",
                CreatedAt = DateTime.UtcNow
            },
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "user:write",
                Description = "Update own user data",
                ResourceServer = "spiceauth",
                CreatedAt = DateTime.UtcNow
            },
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "admin:approve",
                Description = "Approve/reject registration requests",
                ResourceServer = "spiceauth",
                CreatedAt = DateTime.UtcNow
            },
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "admin:users",
                Description = "Manage users (view, edit, deactivate)",
                ResourceServer = "spiceauth",
                CreatedAt = DateTime.UtcNow
            },
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "admin:clients",
                Description = "Manage OAuth clients",
                ResourceServer = "spiceauth",
                CreatedAt = DateTime.UtcNow
            },
            
            // SpiceAPI Scopes
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "api:read",
                Description = "Read data from SpiceAPI",
                ResourceServer = "spiceapi",
                CreatedAt = DateTime.UtcNow
            },
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "api:write",
                Description = "Write data to SpiceAPI",
                ResourceServer = "spiceapi",
                CreatedAt = DateTime.UtcNow
            },
            
            // Discord Bot Scopes
            new Scope
            {
                Id = Guid.NewGuid(),
                Name = "bot:commands",
                Description = "Execute Discord bot commands",
                ResourceServer = "discord_bot",
                CreatedAt = DateTime.UtcNow
            }
        };
        
        await context.Scopes.AddRangeAsync(scopes);
        await context.SaveChangesAsync();
    }
    
    private static async Task SeedOAuthClientsAsync(SpiceAuthDbContext context)
    {
        if (await context.OAuthClients.AnyAsync())
            return;
        
        var clients = new[]
        {
            new OAuthClient
            {
                Id = Guid.NewGuid(),
                ClientId = "spicehub_web",
                ClientSecret = HashClientSecret("dev_secret_spicehub_change_in_production"),
                Name = "SpiceHub Web Application",
                Description = "Main web application for SpiceHub",
                ClientType = ClientType.Confidential,
                RequirePkce = false,
                RequireConsent = false,
                RedirectUris = JsonSerializer.Serialize(new[] 
                { 
                    "http://localhost:3000/auth/callback",
                    "https://spicehub.com/auth/callback" 
                }),
                PostLogoutRedirectUris = JsonSerializer.Serialize(new[] 
                { 
                    "http://localhost:3000",
                    "https://spicehub.com" 
                }),
                AllowedScopes = JsonSerializer.Serialize(new[] 
                { 
                    "openid", "profile", "email", 
                    "user:read", "user:write", 
                    "api:read", "api:write" 
                }),
                AccessTokenLifetime = 900, // 15 minutes
                RefreshTokenLifetime = 604800, // 7 days
                AllowOfflineAccess = true,
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            },
            new OAuthClient
            {
                Id = Guid.NewGuid(),
                ClientId = "discord_bot",
                ClientSecret = HashClientSecret("dev_secret_discord_bot_change_in_production"),
                Name = "Discord Bot",
                Description = "SpiceBot Discord integration",
                ClientType = ClientType.Service,
                RequirePkce = false,
                RequireConsent = false,
                RedirectUris = JsonSerializer.Serialize(Array.Empty<string>()),
                PostLogoutRedirectUris = JsonSerializer.Serialize(Array.Empty<string>()),
                AllowedScopes = JsonSerializer.Serialize(new[] 
                { 
                    "bot:commands", 
                    "api:read" 
                }),
                AccessTokenLifetime = 3600, // 1 hour
                RefreshTokenLifetime = 0, // No refresh tokens for service clients
                AllowOfflineAccess = false,
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            },
            new OAuthClient
            {
                Id = Guid.NewGuid(),
                ClientId = "spicehub_mobile",
                ClientSecret = HashClientSecret(""), // Public client - no secret
                Name = "SpiceHub Mobile App",
                Description = "Mobile application (iOS/Android)",
                ClientType = ClientType.Public,
                RequirePkce = true, // REQUIRED for public clients
                RequireConsent = false,
                RedirectUris = JsonSerializer.Serialize(new[] 
                { 
                    "com.spicehub.app://oauth/callback" 
                }),
                PostLogoutRedirectUris = JsonSerializer.Serialize(new[] 
                { 
                    "com.spicehub.app://logout" 
                }),
                AllowedScopes = JsonSerializer.Serialize(new[] 
                { 
                    "openid", "profile", "email", 
                    "user:read", "user:write", 
                    "api:read" 
                }),
                AccessTokenLifetime = 900,
                RefreshTokenLifetime = 2592000, // 30 days for mobile
                AllowOfflineAccess = true,
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            }
        };
        
        await context.OAuthClients.AddRangeAsync(clients);
        await context.SaveChangesAsync();
    }
    
    private static string HashClientSecret(string secret)
    {
        if (string.IsNullOrEmpty(secret))
            return string.Empty;
        
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}