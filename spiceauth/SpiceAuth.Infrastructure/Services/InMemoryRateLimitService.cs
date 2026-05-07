using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Services.RateLimit;

namespace SpiceAuth.Infrastructure.Services;

public sealed class InMemoryRateLimitService(ILogger<InMemoryRateLimitService> logger) : IRateLimitService
{
    private static readonly TimeSpan DefaultLockDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan CleanupThreshold = TimeSpan.FromHours(1);

    private record Entry(int Attempts, DateTime LockUntil, DateTime LastAttempt);

    private readonly ConcurrentDictionary<string, Entry> _store = new();

    public bool IsBlocked(string bucket, string key)
    {
        var fullKey = $"{bucket}:{key}";
        return _store.TryGetValue(fullKey, out var entry) && entry.LockUntil > DateTime.UtcNow;
    }

    public void RecordFailure(string bucket, string key, int maxAttempts = 5, TimeSpan? lockDuration = null)
    {
        var fullKey = $"{bucket}:{key}";
        var now = DateTime.UtcNow;
        var lockFor = lockDuration ?? DefaultLockDuration;

        _store.AddOrUpdate(
            fullKey,
            _ => new Entry(1, DateTime.MinValue, now),
            (_, old) =>
            {
                var newAttempts = old.Attempts + 1;
                var lockUntil = newAttempts >= maxAttempts ? now.Add(lockFor) : old.LockUntil;
                return new Entry(newAttempts, lockUntil, now);
            });

        if (_store.TryGetValue(fullKey, out var current) && current.LockUntil > now)
            logger.LogWarning("Rate limit: {Bucket}/{Key} locked until {Until}", bucket, key, current.LockUntil);
    }

    public void ClearFailures(string bucket, string key)
        => _store.TryRemove($"{bucket}:{key}", out _);

    /// <summary>Removes stale entries. Call periodically from a background service.</summary>
    public int Cleanup()
    {
        var cutoff = DateTime.UtcNow - CleanupThreshold;
        var stale = _store
            .Where(kv => kv.Value.LastAttempt < cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in stale)
            _store.TryRemove(key, out _);

        return stale.Count;
    }
}
