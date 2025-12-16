using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents a linked Discord account for a user.
/// Stores Discord OAuth tokens (encrypted at rest).
/// </summary>
public class DiscordAccount : IEntity
{
    public Guid Id { get; set; }
    
    // Relationship (1:1 with User)
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    
    // Discord Identity
    public string DiscordId { get; set; } = null!; // Discord snowflake ID
    public string Username { get; set; } = null!;
    public string Discriminator { get; set; } = null!; // Legacy, but keep for now
    public string? Avatar { get; set; } // Avatar hash
    public string? Email { get; set; } // From Discord OAuth scope
    
    // OAuth Tokens (will be encrypted by infrastructure layer)
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
    public DateTime TokenExpiresAt { get; set; }
    
    // Timestamps
    public DateTime LinkedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime LastSyncedAt { get; set; }
}