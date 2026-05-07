using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.Infrastructure.BackgroundServices;

/// <summary>
/// Checks every 6 hours whether the active signing key is approaching expiry.
/// Pre-generates the next key 7 days before the current one expires so that
/// JWKS consumers have time to update their caches (RFC 8414 key rollover window).
///
/// Trigger manually via POST /api/admin/keys/rotate.
/// </summary>
public sealed class KeyRotationService(
    IServiceScopeFactory scopeFactory,
    ILogger<KeyRotationService> logger) : BackgroundService
{
    private static readonly TimeSpan CheckInterval    = TimeSpan.FromHours(6);
    private static readonly TimeSpan RotationLeadTime = TimeSpan.FromDays(7);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("KeyRotationService started (check every {Hours}h)", (int)CheckInterval.TotalHours);

        // Stagger startup
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAndRotateAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "KeyRotationService: unexpected error");
            }

            await Task.Delay(CheckInterval, stoppingToken);
        }

        logger.LogInformation("KeyRotationService stopped");
    }

    private async Task CheckAndRotateAsync(CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var keyService = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();

        var activeKey = await keyService.GetPrimaryKeyAsync();

        var timeUntilExpiry = activeKey.ExpiresAt - DateTime.UtcNow;

        if (timeUntilExpiry <= TimeSpan.Zero)
        {
            logger.LogWarning("Active signing key {Kid} has EXPIRED — rotating immediately", activeKey.KeyId);
            await keyService.RotateKeysAsync();
            return;
        }

        if (timeUntilExpiry <= RotationLeadTime)
        {
            logger.LogInformation(
                "Active signing key {Kid} expires in {Days:F1} days — rotating (lead time {Lead}d)",
                activeKey.KeyId,
                timeUntilExpiry.TotalDays,
                (int)RotationLeadTime.TotalDays);

            await keyService.RotateKeysAsync();
        }
        else
        {
            logger.LogDebug("Signing key {Kid} valid for {Days:F1} more days — no rotation needed",
                activeKey.KeyId, timeUntilExpiry.TotalDays);
        }
    }
}
