using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Core.Entities.Organization;

public class Organization : BaseEntity
{
    public string Name { get; set; } = null!;
    public string Slug { get; set; } = null!;
    public string? Description { get; set; }
    public string? LogoUrl { get; set; }
    public Guid OwnerId { get; set; }
    public bool IsActive { get; set; }
    
    // JSON field for settings
    public string? Settings { get; set; }
    
    // Navigation properties
    public User Owner { get; set; } = null!;
    public ICollection<OrganizationMember> Members { get; set; } = new List<OrganizationMember>();
    public ICollection<OrganizationInvitation> Invitations { get; set; } = new List<OrganizationInvitation>();
}