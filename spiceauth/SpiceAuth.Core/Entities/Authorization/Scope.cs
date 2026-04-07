namespace SpiceAuth.Core.Entities.Authorization;

public class Scope : BaseEntity
{
    public string Name { get; set; } = null!;
    public string DisplayName { get; set; } = null!;
    public string? Description { get; set; }
    public string Category { get; set; } = null!;
    public bool IsSystemScope { get; set; }
    public bool RequiresConsent { get; set; }

    public ICollection<UserScope> UserScopes { get; set; } = [];
}