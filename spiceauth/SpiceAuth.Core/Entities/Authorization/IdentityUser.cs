namespace SpiceAuth.Core.Entities.Authorization;

public sealed class IdentityUser
{
    public Guid Id { get; set; }
    public string UserName { get; set; } = null!;
    public string Email { get; set; } = null!;
    public bool IsActive { get; set; } = true;

    public ICollection<UserRole> Roles { get; set; } = new List<UserRole>();
}