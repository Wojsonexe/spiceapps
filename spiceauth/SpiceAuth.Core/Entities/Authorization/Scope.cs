namespace SpiceAuth.Core.Entities.Authorization;

public class Scope : BaseEntity
{
    public string Name { get; set; } = null!; // e.g., "read:profile"
    public string DisplayName { get; set; } = null!;
    public string? Description { get; set; }
    public string Category { get; set; } = null!; // "Profile", "Posts", "Admin", "Org"
    public bool IsSystemScope { get; set; }
    public bool RequiresConsent { get; set; }
    
    // Navigation properties
    public ICollection<UserScope> UserScopes { get; set; } = new List<UserScope>();
}