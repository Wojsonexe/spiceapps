using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Security;

public class AuditLog : BaseEntity
{
    public Guid? UserId { get; set; }
    public Guid? ClientId { get; set; }
    public Guid? OrganizationId { get; set; }
    
    public AuditAction Action { get; set; }
    public string? ResourceType { get; set; }
    public string? ResourceId { get; set; }
    
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    
    public bool Success { get; set; }
    public string? FailureReason { get; set; }
    
    // JSON field for additional metadata
    public string? Metadata { get; set; }
    
    public DateTime Timestamp { get; set; }
}