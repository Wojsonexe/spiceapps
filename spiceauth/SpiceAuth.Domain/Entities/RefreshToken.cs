using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents an OAuth 2.0 refresh token.
/// Long-lived token used to obtain new access tokens.
/// Implements token rotation for security.
/// </summary>
public class RefreshToken : IEntity
{
    public Guid Id { get; set; }
    
    // Token Identity (SHA256 hash stored, plain text sent to client)
    public string Token { get; set; } = null!;
    
    // Relationships
    public Guid ClientId { get; set; }
    public OAuthClient Client { get; set; } = null!;
    
    public Guid? UserId { get; set; } // Nullable for client_credentials flow
    public User? User { get; set; }
    
    // OAuth Parameters
    public string Scope { get; set; } = null!;
    
    // Token Rotation Chain
    public Guid? PreviousTokenId { get; set; } // For detecting token reuse attacks
    
    // Status
    public bool IsRevoked { get; set; } = false;
    public DateTime? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
    
    // Timestamps
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    
    // Request Metadata
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}