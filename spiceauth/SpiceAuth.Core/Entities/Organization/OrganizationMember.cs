using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Organization;

public class OrganizationMember : BaseEntity
{
    public Guid OrganizationId { get; set; }
    public Guid UserId { get; set; }
    public OrganizationRole Role { get; set; }
    public DateTime JoinedAt { get; set; } = DateTime.UtcNow;
    public Guid? InvitedByUserId { get; set; }
    public bool IsActive { get; set; } = true;

    // Navigation
    public Organization Organization { get; set; } = null!;
    public ApplicationUser User { get; set; } = null!;
}