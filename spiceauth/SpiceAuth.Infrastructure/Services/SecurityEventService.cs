using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Core.Enums;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Infrastructure.Services;

public sealed class SecurityEventService(
    IServiceScopeFactory scopeFactory,
    ILogger<SecurityEventService> logger) : ISecurityEventService
{
    public void Record(
        Guid userId,
        SecurityEventType type,
        SecurityEventSeverity severity,
        string description,
        string? ipAddress = null)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await using var scope = scopeFactory.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                db.Set<SecurityEvent>().Add(new SecurityEvent
                {
                    UserId      = userId,
                    EventType   = type,
                    Severity    = severity,
                    Description = description,
                    IpAddress   = ipAddress,
                    Resolved    = false,
                    Timestamp   = DateTime.UtcNow
                });

                await db.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to persist SecurityEvent {Type} for user {UserId}", type, userId);
            }
        });
    }
}
