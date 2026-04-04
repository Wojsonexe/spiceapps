namespace SpiceAuth.Core.Entities.OAuth;

public class AuthCode : BaseEntity
{
    public string Code { get; set; } = null!;
    public Guid UserId { get; set; }
    public Guid ClientId { get; set; }
    public string RedirectUri { get; set; } = null!;
    public string Scope { get; set; } = null!;
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    
    // Security & Expiry
    public bool IsUsed { get; set; }
    public DateTime IssuedAt { get; set; }
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddMinutes(10);
    
    // Navigation
    public OAuthClient Client { get; set; } = null!;
}