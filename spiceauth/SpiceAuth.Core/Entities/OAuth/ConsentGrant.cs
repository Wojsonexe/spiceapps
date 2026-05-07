namespace SpiceAuth.Core.Entities.OAuth;

public class ConsentGrant : BaseEntity
{
    public Guid UserId { get; set; }
    public Guid ClientId { get; set; }
    public string Scope { get; set; } = null!;          // space-separated
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }

    /// <summary>Version of the client's consent requirements at time of grant. Re-consent required if client bumps its version.</summary>
    public int ConsentVersion { get; set; } = 1;

    public DateTime? LastUsedAt { get; set; }

    // Navigation
    public OAuthClient Client { get; set; } = null!;
}