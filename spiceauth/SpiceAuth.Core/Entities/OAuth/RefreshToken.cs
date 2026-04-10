namespace SpiceAuth.Core.Entities.OAuth;

public class RefreshToken
{
    public Guid Id { get; set; }
    public string TokenHash { get; set; } = null!;
    public Guid UserId { get; set; }
    public Guid ClientId { get; set; }
    public string? DeviceId { get; set; }
    public string Scope { get; set; } = null!;
    public bool IsRevoked { get; set; }
    public bool IsUsed { get; set; }
    public Guid? ParentTokenId { get; set; }
    public Guid? ReplacedByTokenId { get; set; }
    public Guid? FamilyId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public Guid? OrganizationId { get; set; }

    public OAuthClient? Client { get; set; }
    public RefreshToken? ParentToken { get; set; }
}