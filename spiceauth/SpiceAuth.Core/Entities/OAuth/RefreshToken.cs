// SpiceAuth.Core/Entities/OAuth/RefreshToken.cs

using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Core.Entities.OAuth;

public class RefreshToken : BaseEntity
{
    public string TokenHash { get; set; } = null!;      // SHA-256 of actual token
    public Guid ClientId { get; set; }
    public Guid UserId { get; set; }
    public string Scope { get; set; } = null!;

    public bool IsRevoked { get; set; }
    public bool IsUsed { get; set; }
    public DateTime ExpiresAt { get; set; }

    public Guid? ParentTokenId { get; set; }            // Token rotation chain
    public Guid? OrganizationId { get; set; }

    // Navigation
    public OAuthClient Client { get; set; } = null!;
    public ApplicationUser User { get; set; } = null!;
    public RefreshToken? ParentToken { get; set; }
}