using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents an authenticated user in the system.
/// Created only after registration request approval.
/// </summary>
public class User : IEntity
{
    public Guid Id { get; set; }
    
    // Identity
    public string Email { get; set; } = null!;
    public string NormalizedEmail { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string PasswordHash { get; set; } = null!;
    
    // Status
    public bool IsActive { get; set; } = true;
    public bool IsLocked { get; set; } = false;
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockedUntil { get; set; }
    
    // Timestamps
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
    
    // Navigation Properties
    public DiscordAccount? DiscordAccount { get; set; }
    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<UserScope> UserScopes { get; set; } = new List<UserScope>();
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    public ICollection<OAuthAuthorizationCode> AuthorizationCodes { get; set; } = new List<OAuthAuthorizationCode>();
}