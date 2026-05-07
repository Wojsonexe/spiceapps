using SpiceAuth.Application.Services.RateLimit;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.API.Services;

public sealed class RateLimitCleanupService(
    IRateLimitService rateLimiter,
    ILogger<RateLimitCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Rate limit cleanup service started (hourly)");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);

                if (rateLimiter is InMemoryRateLimitService impl)
                {
                    var removed = impl.Cleanup();
                    if (removed > 0)
                        logger.LogInformation("Rate limit cleanup: {Removed} stale entries removed", removed);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Rate limit cleanup error");
            }
        }

        logger.LogInformation("Rate limit cleanup service stopped");
    }
}
