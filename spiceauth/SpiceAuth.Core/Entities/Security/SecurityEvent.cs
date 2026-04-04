using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Security;

public class SecurityEvent : BaseEntity
{
    public Guid UserId { get; set; }
    public SecurityEventType EventType { get; set; }
    public SecurityEventSeverity Severity { get; set; }
    public string Description { get; set; } = null!;
    
    public string? IpAddress { get; set; }
    public bool Resolved { get; set; }
    public Guid? ResolvedByUserId { get; set; }
    public DateTime Timestamp { get; set; }
    
}