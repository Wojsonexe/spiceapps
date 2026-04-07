using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.OAuth;

public class OAuthClient : BaseEntity
{
    public string ClientId { get; set; } = null!;
    public string? ClientSecretHash { get; set; }       // null dla public clients

    public string Name { get; set; } = null!;
    public string? Description { get; set; }
    public string? LogoUrl { get; set; }

    public ClientType ClientType { get; set; }          // Public | Confidential | Mobile

    // Stored as JSON arrays
    public string RedirectUris { get; set; } = "[]";
    public string PostLogoutRedirectUris { get; set; } = "[]";
    public string AllowedScopes { get; set; } = "[]";
    public string AllowedGrantTypes { get; set; } = "[]";

    public bool RequireConsent { get; set; }
    public bool RequirePkce { get; set; }
    public int AccessTokenLifetime { get; set; } = 900;
    public int RefreshTokenLifetime { get; set; } = 604800;
    public bool IsActive { get; set; } = true;

    public Guid CreatedByUserId { get; set; }
    public Guid? OrganizationId { get; set; }

    // Navigation
    public Organization.Organization? Organization { get; set; }
    public ICollection<AuthorizationCode> AuthorizationCodes { get; set; } = [];
    public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
    public ICollection<ConsentGrant> ConsentGrants { get; set; } = [];
}