using SpiceAuth.API.Controllers;

namespace SpiceAuth.API.Services;

public class RateLimitCleanupService : BackgroundService
{
    private readonly ILogger<RateLimitCleanupService> _logger;

    public RateLimitCleanupService(ILogger<RateLimitCleanupService> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("🧹 Rate limit cleanup service started");
        
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
                
                var (clientsRemoved, loginsRemoved) = OAuthController.CleanupExpiredLocks();
                
                if (clientsRemoved > 0 || loginsRemoved > 0)
                {
                    _logger.LogInformation(
                        "🧹 Rate limit cleanup: {ClientsRemoved} client locks, {LoginsRemoved} login locks removed",
                        clientsRemoved, loginsRemoved);
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Rate limit cleanup error");
            }
        }
        
        _logger.LogInformation("🧹 Rate limit cleanup service stopped");
    }
}