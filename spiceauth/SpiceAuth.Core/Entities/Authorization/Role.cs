namespace SpiceAuth.Core.Entities.Authorization;

public class Role : BaseEntity
{
    public string Name { get; set; } = null!;
    public string NormalizedName { get; set; } = null!;
    public string? Description { get; set; }
    public bool IsSystemRole { get; set; }
    public string? Permissions { get; set; }

    public ICollection<UserRole> UserRoles { get; set; } = [];
}