using SpiceAuth.Domain.Enums;
using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents an OAuth 2.0/OIDC client application.
/// </summary>
public class OAuthClient : IEntity
{
    public Guid Id { get; set; }
    
    // Client Identity
    public string ClientId { get; set; } = null!; // Human-readable ID (e.g., "spicehub_web")
    public string ClientSecret { get; set; } = null!; // Hashed with SHA256
    public string Name { get; set; } = null!; // Display name
    public string? Description { get; set; }
    
    // Client Configuration
    public ClientType ClientType { get; set; }
    public bool RequirePkce { get; set; } = false;
    public bool RequireConsent { get; set; } = false;
    
    // URIs (stored as JSON array strings)
    public string RedirectUris { get; set; } = "[]";
    public string? PostLogoutRedirectUris { get; set; } = "[]";
    
    // Scopes (stored as JSON array string)
    public string AllowedScopes { get; set; } = "[]";
    
    // Token Settings
    public int AccessTokenLifetime { get; set; } = 900; // 15 minutes
    public int RefreshTokenLifetime { get; set; } = 604800; // 7 days
    public bool AllowOfflineAccess { get; set; } = true;
    
    // Status
    public bool IsActive { get; set; } = true;
    
    // Timestamps
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    
    // Navigation Properties
    public ICollection<OAuthAuthorizationCode> AuthorizationCodes { get; set; } = new List<OAuthAuthorizationCode>();
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}