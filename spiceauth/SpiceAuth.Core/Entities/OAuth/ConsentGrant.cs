namespace SpiceAuth.Core.Entities.OAuth;

public class ConsentGrant : BaseEntity
{
    public Guid UserId { get; set; }
    public Guid ClientId { get; set; }
    public string Scope { get; set; } = null!;
    public DateTime GrantedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool IsRevoked { get; set; }
    
    // Navigation
    public OAuthClient Client { get; set; } = null!;
}