namespace SpiceAuth.Core.Entities.OAuth;

public class RefreshToken : BaseEntity
{
    public string TokenHash { get; set; } = null!;
    public Guid ClientId { get; set; }
    public Guid UserId { get; set; }
    public string Scope { get; set; } = null!;
    
    public bool IsRevoked { get; set; }
    public bool IsUsed { get; set; }
    public DateTime ExpiresAt { get; set; }
    
    // Token rotation
    public Guid? ParentTokenId { get; set; }
    
    public Guid? OrganizationId { get; set; }
    
    // Navigation
    public OAuthClient Client { get; set; } = null!;
    public RefreshToken? ParentToken { get; set; }
}