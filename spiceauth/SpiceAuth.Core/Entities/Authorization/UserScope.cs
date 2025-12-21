using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Core.Entities.Authorization;

public class UserScope
{
    public Guid UserId { get; set; }
    public Guid ScopeId { get; set; }
    public DateTime GrantedAt { get; set; }
    public Guid? GrantedByUserId { get; set; }
    public DateTime? ExpiresAt { get; set; }
    
    // Navigation properties
    public User User { get; set; } = null!;
    public Scope Scope { get; set; } = null!;
}