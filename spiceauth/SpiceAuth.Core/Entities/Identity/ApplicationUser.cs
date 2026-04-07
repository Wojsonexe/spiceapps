using Microsoft.AspNetCore.Identity;
using SpiceAuth.Core.Entities.Authorization;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Organization;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Core.Entities.Identity;

public class ApplicationUser : IdentityUser<Guid>
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? ProfilePictureUrl { get; set; }

    public bool IsActive { get; set; } = true;
    public bool IsSuspended { get; set; }
    public DateTime? SuspendedUntil { get; set; }

    public decimal Coin { get; set; } = 0;
    public DateOnly? BirthDay { get; set; }
    public int Department { get; set; }
    public bool IsApproved { get; set; }

    public string? DiscordId { get; set; }
    public string? DiscordUsername { get; set; }

    public DateTime? LastLoginAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    // Navigation properties
    public ICollection<ExternalIdentity> ExternalIdentities { get; set; } = [];
    public ICollection<UserRole> UserRoles { get; set; } = [];
    public ICollection<UserScope> UserScopes { get; set; } = [];
    public ICollection<RefreshToken> RefreshTokens { get; set; } = [];
    public ICollection<OrganizationMember> OrganizationMemberships { get; set; } = [];
    public MfaSettings? MfaSettings { get; set; }
}