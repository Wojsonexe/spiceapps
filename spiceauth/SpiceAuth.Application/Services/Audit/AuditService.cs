using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Core.Entities.Security;
using System.Text.Json;

namespace SpiceAuth.Application.Services.Audit;

public class AuditService(
    DbContext context,
    ILogger<AuditService> logger) : IAuditService
{
    public async Task LogAsync(
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
        string? userAgent = null)
    {
        if (metadata != null)
        {
            var trimmed = metadata.TrimStart();
            if (!trimmed.StartsWith("{") && !trimmed.StartsWith("["))
                metadata = JsonSerializer.Serialize(new { value = metadata });
        }

        var entry = new AuditLog
        {
            Id           = Guid.NewGuid(),
            Action       = action,
            ActorEmail   = actorEmail,
            UserId       = actorId,
            ClientId     = clientId,
            ResourceType = resourceType,
            ResourceId   = resourceId,
            ResourceName = resourceName,
            Success      = success,
            FailureReason = failureReason,
            Metadata     = metadata,
            IpAddress    = ipAddress,
            UserAgent    = userAgent,
            Timestamp    = DateTime.UtcNow
        };

        context.Set<AuditLog>().Add(entry);
        await context.SaveChangesAsync();

        logger.LogInformation(
            "Audit [{Action}] by {Actor} on {ResourceType}/{ResourceName} — {Result}",
            action, actorEmail, resourceType, resourceName,
            success ? "OK" : $"FAILED: {failureReason}");
    }

    public async Task<(List<AuditLog> Items, int Total)> GetLogsAsync(
        int page = 1,
        int pageSize = 50,
        string? search = null,
        AuditAction? action = null)
    {
        var query = context.Set<AuditLog>().AsQueryable();

        if (action.HasValue)
            query = query.Where(l => l.Action == action.Value);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var q = search.ToLower();
            query = query.Where(l =>
                l.ActorEmail.ToLower().Contains(q) ||
                (l.ResourceName != null && l.ResourceName.ToLower().Contains(q)) ||
                (l.ResourceId   != null && l.ResourceId.ToLower().Contains(q)));
        }

        var total = await query.CountAsync();
        var items = await query
            .OrderByDescending(l => l.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (items, total);
    }
}
