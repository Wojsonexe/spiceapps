using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents a permission scope (fine-grained permissions).
/// </summary>
public class Scope : IEntity
{
    public Guid Id { get; set; }
    
    public string Name { get; set; } = null!; // e.g., "user:read", "admin:approve"
    public string? Description { get; set; }
    public string ResourceServer { get; set; } = null!; // e.g., "spiceapi", "spicehub", "all"
    
    public DateTime CreatedAt { get; set; }
    
    // Navigation Properties
    public ICollection<UserScope> UserScopes { get; set; } = new List<UserScope>();
}