namespace SpiceAuth.Core.Entities.OAuth;

public class AuthorizationCode : BaseEntity
{
    public string Code { get; set; } = null!;
    public Guid ClientId { get; set; }
    public Guid UserId { get; set; }
    public string RedirectUri { get; set; } = null!;
    public string Scope { get; set; } = null!;
    
    // PKCE
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    
    // OIDC
    public string? Nonce { get; set; }
    
    public bool IsUsed { get; set; }
    public DateTime ExpiresAt { get; set; }
    
    // Navigation
    public OAuthClient Client { get; set; } = null!;
}