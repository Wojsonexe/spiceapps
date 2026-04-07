// SpiceAuth.Core/Entities/Security/AuditLog.cs
using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Security;

public class AuditLog : BaseEntity
{
    public Guid? UserId { get; set; }
    public string ActorEmail { get; set; } = null!;

    public Guid? ClientId { get; set; }
    public Guid? OrganizationId { get; set; }

    public AuditAction Action { get; set; }

    public string? ResourceType { get; set; }
    public string? ResourceId { get; set; }
    public string? ResourceName { get; set; }

    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    public bool Success { get; set; }
    public string? FailureReason { get; set; }
    public string? Metadata { get; set; }               // JSON

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}