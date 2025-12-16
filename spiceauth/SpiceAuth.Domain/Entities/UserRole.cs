using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Junction table for User-Role many-to-many relationship.
/// </summary>
public class UserRole
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;
    
    public DateTime GrantedAt { get; set; }
}