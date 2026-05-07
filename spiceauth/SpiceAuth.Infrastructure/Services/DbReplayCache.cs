using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Infrastructure.Services;

/// <summary>
/// DB-backed replay cache. Uses the existing <c>logout_token_jtis</c> table pattern
/// for logout tokens, and a generalized <c>replay_cache</c> for other identifiers.
///
/// Single-source-of-truth: works correctly across multiple nodes sharing the same DB.
/// For high-throughput scenarios, swap for a Redis-backed implementation.
/// </summary>
public sealed class DbReplayCache(
    IServiceScopeFactory scopeFactory,
    ILogger<DbReplayCache> logger) : IReplayCache
{
    public async Task<bool> TryRecordAsync(string bucket, string key, TimeSpan ttl, CancellationToken ct = default)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        if (bucket == "logout_jti")
        {
            // JTI values are kept as-is in the dedicated table (already hashed by caller convention)
            var exists = await db.Set<LogoutTokenJti>()
                .AnyAsync(j => j.Jti == key, ct);

            if (exists) return false;

            try
            {
                db.Set<LogoutTokenJti>().Add(new LogoutTokenJti { Jti = key, UsedAt = DateTime.UtcNow });
                await db.SaveChangesAsync(ct);
                return true;
            }
            catch (DbUpdateException)
            {
                logger.LogDebug("Replay cache: concurrent JTI insert for key …{Tail}",
                    key.Length > 8 ? key[^8..] : key);
                return false;
            }
        }

        // Generic bucket — store SHA256(bucket:key) to keep raw values out of the DB
        var entryKey   = HashEntryKey(bucket, key);
        var entryExists = await db.Set<ReplayCacheEntry>()
            .AnyAsync(e => e.EntryKey == entryKey && e.ExpiresAt > DateTime.UtcNow, ct);

        if (entryExists) return false;

        try
        {
            db.Set<ReplayCacheEntry>().Add(new ReplayCacheEntry
            {
                EntryKey   = entryKey,
                Bucket     = bucket,
                RecordedAt = DateTime.UtcNow,
                ExpiresAt  = DateTime.UtcNow.Add(ttl)
            });
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateException)
        {
            logger.LogDebug("Replay cache: concurrent insert for bucket={Bucket}", bucket);
            return false;
        }
    }

    public async Task<bool> IsRecordedAsync(string bucket, string key, CancellationToken ct = default)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        if (bucket == "logout_jti")
            return await db.Set<LogoutTokenJti>().AnyAsync(j => j.Jti == key, ct);

        var entryKey = HashEntryKey(bucket, key);
        return await db.Set<ReplayCacheEntry>()
            .AnyAsync(e => e.EntryKey == entryKey && e.ExpiresAt > DateTime.UtcNow, ct);
    }

    // SHA256(bucket:key) stored as hex — prevents raw values from appearing in DB
    private static string HashEntryKey(string bucket, string key)
        => Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes($"{bucket}:{key}")));
}
