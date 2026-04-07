namespace SpiceAuth.Core.Entities.Identity;

public class ExternalIdentity : BaseEntity
{
    public Guid UserId { get; set; }
    public string Provider { get; set; } = null!;       // "discord" | "google" | "github"
    public string ProviderUserId { get; set; } = null!;
    public string? ProviderUsername { get; set; }
    public string? ProviderEmail { get; set; }
    public string? AccessToken { get; set; }            // Encrypted at rest
    public string? RefreshToken { get; set; }           // Encrypted at rest
    public DateTime? ExpiresAt { get; set; }
    public DateTime LinkedAt { get; set; } = DateTime.UtcNow;

    // Navigation
    public ApplicationUser User { get; set; } = null!;
}