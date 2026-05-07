namespace SpiceAuth.Core.Entities.Organization;

/// <summary>
/// Tenant foundation for future multi-tenant SaaS.
/// Nullable/additive — existing single-tenant flows are unaffected.
/// </summary>
public class Tenant
{
    public Guid Id { get; set; }

    /// <summary>URL-safe unique identifier (e.g. "spicegears").</summary>
    public string Slug { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<TenantMembership> Memberships { get; set; } = new List<TenantMembership>();
}
