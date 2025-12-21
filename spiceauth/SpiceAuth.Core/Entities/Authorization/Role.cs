namespace SpiceAuth.Core.Entities.Authorization;

public class Role : BaseEntity
{
    public string Name { get; set; } = null!;
    public string? Description { get; set; }
    public bool IsSystemRole { get; set; }
    
    // JSON field for policy definitions (ABAC)
    public string? Permissions { get; set; }
    
    // Navigation properties
    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}