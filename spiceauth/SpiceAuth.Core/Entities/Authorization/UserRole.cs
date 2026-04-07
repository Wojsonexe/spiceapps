using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Core.Entities.Authorization;

public class UserRole
{
    public Guid UserId { get; set; }
    public Guid RoleId { get; set; }
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
    public Guid? AssignedByUserId { get; set; }

    // Navigation
    public ApplicationUser User { get; set; } = null!;
    public Role Role { get; set; } = null!;
}