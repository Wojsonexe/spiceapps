using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Organization;

public class OrganizationInvitation : BaseEntity
{
    public Guid OrganizationId { get; set; }
    public string Email { get; set; } = null!;
    public OrganizationRole Role { get; set; }
    public Guid InvitedByUserId { get; set; }
    public string Token { get; set; } = null!;
    public DateTime ExpiresAt { get; set; }
    public DateTime? AcceptedAt { get; set; }
    public bool IsRevoked { get; set; }
    
    // Navigation properties
    public Organization Organization { get; set; } = null!;
    public User InvitedBy { get; set; } = null!;
}