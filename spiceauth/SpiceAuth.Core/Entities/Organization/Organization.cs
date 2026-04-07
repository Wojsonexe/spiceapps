using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Core.Entities.Organization;

public class Organization : BaseEntity
{
    public string Name { get; set; } = null!;
    public string Slug { get; set; } = null!;
    public string? Description { get; set; }
    public string? LogoUrl { get; set; }
    public Guid OwnerId { get; set; }
    public bool IsActive { get; set; } = true;
    public string? Settings { get; set; }               // JSON

    // Navigation
    public ICollection<OrganizationMember> Members { get; set; } = [];
    public ICollection<OrganizationInvitation> Invitations { get; set; } = [];
    public ICollection<OAuthClient> Clients { get; set; } = [];
}