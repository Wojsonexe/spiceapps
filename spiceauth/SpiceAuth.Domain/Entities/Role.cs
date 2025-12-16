using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents a user role (coarse-grained permissions).
/// </summary>
public class Role : IEntity
{
    public Guid Id { get; set; }
    
    public string Name { get; set; } = null!; // e.g., "Admin", "User"
    public string? Description { get; set; }
    public bool IsSystemRole { get; set; } = false; // System roles cannot be deleted
    
    public DateTime CreatedAt { get; set; }
    
    // Navigation Properties
    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}