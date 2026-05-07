using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using SpiceAuth.Infrastructure.Data;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Verifies DbReplayCache security properties:
/// - First recording returns true; duplicate returns false
/// - Bucket isolation (different buckets are independent namespaces)
/// - logout_jti path (dedicated table, no TTL expiry check)
/// - Hashing: raw values must not appear in the stored key
/// </summary>
public class ReplayCacheTests : IDisposable
{
    private readonly ServiceProvider _sp;
    private readonly DbReplayCache _cache;

    public ReplayCacheTests()
    {
        var services = new ServiceCollection();
        services.AddDbContext<ApplicationDbContext>(o =>
            o.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        _sp = services.BuildServiceProvider();

        _cache = new DbReplayCache(
            _sp.GetRequiredService<IServiceScopeFactory>(),
            new Mock<ILogger<DbReplayCache>>().Object);
    }

    // ── TryRecordAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task TryRecord_NewKey_ReturnsTrue()
    {
        var result = await _cache.TryRecordAsync("auth_code", "unique-key-abc123", TimeSpan.FromMinutes(5));
        Assert.True(result);
    }

    [Fact]
    public async Task TryRecord_DuplicateKey_ReturnsFalse()
    {
        const string key = "duplicate-key-xyz-789";
        await _cache.TryRecordAsync("auth_code", key, TimeSpan.FromMinutes(5));

        var second = await _cache.TryRecordAsync("auth_code", key, TimeSpan.FromMinutes(5));
        Assert.False(second);
    }

    [Fact]
    public async Task TryRecord_SameKeyDifferentBuckets_BothReturnTrue()
    {
        // Namespacing — same key in different buckets is independent
        const string key = "shared-key-abc";
        var first  = await _cache.TryRecordAsync("bucket-alpha", key, TimeSpan.FromMinutes(5));
        var second = await _cache.TryRecordAsync("bucket-beta",  key, TimeSpan.FromMinutes(5));

        Assert.True(first);
        Assert.True(second);
    }

    [Fact]
    public async Task TryRecord_MultipleUniqueKeys_AllReturnTrue()
    {
        var results = await Task.WhenAll(
            _cache.TryRecordAsync("test", "key-1", TimeSpan.FromMinutes(5)),
            _cache.TryRecordAsync("test", "key-2", TimeSpan.FromMinutes(5)),
            _cache.TryRecordAsync("test", "key-3", TimeSpan.FromMinutes(5)));

        Assert.All(results, r => Assert.True(r));
    }

    // ── logout_jti specialisation ─────────────────────────────────────────────

    [Fact]
    public async Task TryRecord_LogoutJti_FirstReturnsTrueSecondReturnsFalse()
    {
        var jti    = Guid.NewGuid().ToString();
        var first  = await _cache.TryRecordAsync("logout_jti", jti, TimeSpan.FromMinutes(10));
        var second = await _cache.TryRecordAsync("logout_jti", jti, TimeSpan.FromMinutes(10));

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public async Task TryRecord_DifferentLogoutJtis_BothReturnTrue()
    {
        var first  = await _cache.TryRecordAsync("logout_jti", Guid.NewGuid().ToString(), TimeSpan.FromMinutes(10));
        var second = await _cache.TryRecordAsync("logout_jti", Guid.NewGuid().ToString(), TimeSpan.FromMinutes(10));

        Assert.True(first);
        Assert.True(second);
    }

    // ── IsRecordedAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task IsRecorded_AfterRecord_ReturnsTrue()
    {
        const string key = "is-recorded-test-key";
        await _cache.TryRecordAsync("test", key, TimeSpan.FromMinutes(5));

        var recorded = await _cache.IsRecordedAsync("test", key);
        Assert.True(recorded);
    }

    [Fact]
    public async Task IsRecorded_KeyNeverRecorded_ReturnsFalse()
    {
        var recorded = await _cache.IsRecordedAsync("test", "never-recorded-key-xyz");
        Assert.False(recorded);
    }

    [Fact]
    public async Task IsRecorded_WrongBucket_ReturnsFalse()
    {
        await _cache.TryRecordAsync("bucket-a", "cross-bucket-key", TimeSpan.FromMinutes(5));
        // Querying a different bucket for the same key — should not find it
        var recorded = await _cache.IsRecordedAsync("bucket-b", "cross-bucket-key");
        Assert.False(recorded);
    }

    // ── Raw-value hashing verification ────────────────────────────────────────

    [Fact]
    public async Task TryRecord_GenericBucket_DoesNotStoreRawKeyInDb()
    {
        const string sensitiveKey = "raw-jti-value-that-must-not-appear-in-db";
        await _cache.TryRecordAsync("auth_code", sensitiveKey, TimeSpan.FromMinutes(5));

        // The raw key must NOT be stored — only the SHA256 hash should appear
        await using var scope = _sp.GetRequiredService<IServiceScopeFactory>().CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        var entries = await db.Set<SpiceAuth.Core.Entities.Security.ReplayCacheEntry>()
            .ToListAsync();

        // EntryKey should be a hex SHA256 digest (64 hex chars), never the raw value
        Assert.All(entries, e =>
        {
            Assert.DoesNotContain(sensitiveKey, e.EntryKey, StringComparison.Ordinal);
            Assert.Equal(64, e.EntryKey.Length); // SHA256 = 32 bytes = 64 hex chars
            Assert.Matches("^[0-9A-F]{64}$", e.EntryKey); // uppercase hex from Convert.ToHexString
        });
    }

    public void Dispose() => _sp.Dispose();
}
