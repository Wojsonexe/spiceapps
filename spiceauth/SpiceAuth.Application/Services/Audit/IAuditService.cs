using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Services.Audit;

public interface IAuditService
{
    Task LogAsync(
        AuditAction action,
        string actorEmail,
        Guid? actorId = null,
        Guid? clientId = null,
        string? resourceType = null,
        string? resourceId = null,
        string? resourceName = null,
        bool success = true,
        string? failureReason = null,
        string? metadata = null,
        string? ipAddress = null,
        string? userAgent = null);

    Task<(List<AuditLog> Items, int Total)> GetLogsAsync(
        int page = 1,
        int pageSize = 50,
        string? search = null,
        AuditAction? action = null);
}