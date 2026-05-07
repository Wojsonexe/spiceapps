using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Infrastructure.BackgroundServices;

/// <summary>
/// Periodic cleanup of expired/stale data:
/// - Expired GlobalSessions (and their AppSessions, cascaded)
/// - Expired AuthorizationCodes
/// - Expired RefreshTokens
/// - Old LogoutTokenJti entries (replay store TTL)
/// - Stale AppSession registrations (app went offline)
///
/// Runs every 30 minutes. All operations are idempotent.
/// </summary>
public sealed class SessionCleanupService(
    IServiceScopeFactory scopeFactory,
    ILogger<SessionCleanupService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval           = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan JtiRetentionPeriod = TimeSpan.FromHours(24);
    private static readonly TimeSpan StaleAppSession    = TimeSpan.FromDays(30);
    private const int JtiDeleteBatchSize = 1_000;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("SessionCleanupService started (interval={Interval}min)",
            (int)Interval.TotalMinutes);

        // Stagger startup so it doesn't hit the DB at the same time as migrations
        await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunCleanupAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "SessionCleanupService: unhandled error during cleanup");
            }

            await Task.Delay(Interval, stoppingToken);
        }

        logger.LogInformation("SessionCleanupService stopped");
    }

    private async Task RunCleanupAsync(CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var now = DateTime.UtcNow;

        // ── GlobalSessions ────────────────────────────────────────────────────
        var expiredSessions = await db.Set<GlobalSession>()
            .Where(s => s.ExpiresAt < now)
            .ExecuteDeleteAsync(ct);

        // ── AuthorizationCodes ────────────────────────────────────────────────
        var expiredCodes = await db.Set<AuthorizationCode>()
            .Where(c => c.ExpiresAt < now)
            .ExecuteDeleteAsync(ct);

        // ── RefreshTokens ─────────────────────────────────────────────────────
        var expiredTokens = await db.Set<RefreshToken>()
            .Where(t => t.ExpiresAt < now || (t.IsRevoked && t.CreatedAt < now.AddDays(-7)))
            .ExecuteDeleteAsync(ct);

        // ── LogoutTokenJtis (replay store) — batched to avoid long table locks ──
        var jtiCutoff = now - JtiRetentionPeriod;
        int oldJtis = 0;
        int batch;
        do
        {
            batch = await db.Set<LogoutTokenJti>()
                .Where(j => j.UsedAt < jtiCutoff)
                .Take(JtiDeleteBatchSize)
                .ExecuteDeleteAsync(ct);
            oldJtis += batch;
        } while (batch == JtiDeleteBatchSize && !ct.IsCancellationRequested);

        // ── Stale AppSessions (app never checked in) ──────────────────────────
        var staleAppCutoff = now - StaleAppSession;
        var staleApps = await db.Set<AppSession>()
            .Where(a => a.LastSeenAt < staleAppCutoff)
            .ExecuteDeleteAsync(ct);

        // ── ReplayCacheEntry (generic replay-protection store, Phase 3H) ──────
        var expiredCacheEntries = await db.Set<ReplayCacheEntry>()
            .Where(r => r.ExpiresAt < now)
            .ExecuteDeleteAsync(ct);

        if (expiredSessions + expiredCodes + expiredTokens + oldJtis + staleApps + expiredCacheEntries > 0)
        {
            logger.LogInformation(
                "Cleanup: GlobalSessions={Gs} AuthCodes={Ac} RefreshTokens={Rt} JTIs={Jti} StaleApps={Sa} ReplayCache={Rc}",
                expiredSessions, expiredCodes, expiredTokens, oldJtis, staleApps, expiredCacheEntries);
        }
    }
}
