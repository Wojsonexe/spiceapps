using SpiceAuth.Core.Enums;

namespace SpiceAuth.Application.Services.Security;

/// <summary>
/// Fire-and-forget security event recorder. Writes are non-blocking —
/// callers are never delayed by DB I/O on the security event path.
/// </summary>
public interface ISecurityEventService
{
    void Record(
        Guid userId,
        SecurityEventType type,
        SecurityEventSeverity severity,
        string description,
        string? ipAddress = null);
}
