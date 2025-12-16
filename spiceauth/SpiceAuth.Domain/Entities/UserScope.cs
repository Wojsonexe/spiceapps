using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Junction table for User-Scope many-to-many relationship.
/// Tracks who granted the scope for audit purposes.
/// </summary>
public class UserScope
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    
    public Guid ScopeId { get; set; }
    public Scope Scope { get; set; } = null!;
    
    public Guid GrantedByUserId { get; set; }
    public User GrantedBy { get; set; } = null!;
    
    public DateTime GrantedAt { get; set; }
}