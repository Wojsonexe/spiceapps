using SpiceAuth.Core.Entities.Authorization;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Organization;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Core.Entities.Identity;

public class User : BaseEntity
{
    public string Email { get; set; } = null!;
    public bool EmailConfirmed { get; set; }
    public string Username { get; set; } = null!;
    public string? PasswordHash { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? ProfilePictureUrl { get; set; }
    public bool IsActive { get; set; }
    public bool IsSuspended { get; set; }
    public DateTime? SuspendedUntil { get; set; }
    public DateTime? LastLoginAt { get; set; }
    
    // Navigation properties
    public ICollection<ExternalIdentity> ExternalIdentities { get; set; } = new List<ExternalIdentity>();
    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<UserScope> UserScopes { get; set; } = new List<UserScope>();
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    public ICollection<OrganizationMember> OrganizationMemberships { get; set; } = new List<OrganizationMember>();
    public ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
    public MfaSettings? MfaSettings { get; set; }
}