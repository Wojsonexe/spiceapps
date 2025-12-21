namespace SpiceAuth.Core.Entities.Identity;

public class ExternalIdentity : BaseEntity
{
    public Guid UserId { get; set; }
    public string Provider { get; set; } = null!; // "discord", "google", "github"
    public string ProviderUserId { get; set; } = null!;
    public string? ProviderUsername { get; set; }
    public string? ProviderEmail { get; set; }
    public string? AccessToken { get; set; } // Encrypted
    public string? RefreshToken { get; set; } // Encrypted
    public DateTime? ExpiresAt { get; set; }
    public DateTime LinkedAt { get; set; }
    
    // Navigation
    public User User { get; set; } = null!;
}