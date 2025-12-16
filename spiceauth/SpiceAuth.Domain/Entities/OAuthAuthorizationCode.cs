using SpiceAuth.Domain.Enums;
using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents an OAuth 2.0 authorization code.
/// Short-lived (10 minutes), single-use token.
/// </summary>
public class OAuthAuthorizationCode : IEntity
{
    public Guid Id { get; set; }
    
    // Code Identity (SHA256 hash stored, plain text sent to client)
    public string Code { get; set; } = null!;
    
    // Relationships
    public Guid ClientId { get; set; }
    public OAuthClient Client { get; set; } = null!;
    
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    
    // OAuth Parameters
    public string RedirectUri { get; set; } = null!;
    public string Scope { get; set; } = null!; // Space-separated
    public string? Nonce { get; set; } // OIDC nonce for ID token
    
    // PKCE (RFC 7636)
    public string? CodeChallenge { get; set; }
    public CodeChallengeMethod? CodeChallengeMethod { get; set; }
    
    // Status
    public bool IsUsed { get; set; } = false;
    public DateTime? UsedAt { get; set; }
    
    // Timestamps
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}