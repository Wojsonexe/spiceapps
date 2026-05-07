using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Services;

public interface IKeyManagementService
{
    /// <summary>Returns the current primary signing key (used to sign new JWTs).</summary>
    Task<SigningKey> GetPrimaryKeyAsync();

    /// <summary>Returns all active keys (primary + recently-active non-retired) for JWKS/verification.</summary>
    Task<List<SigningKey>> GetActiveKeysAsync();

    /// <summary>Creates a new RSA keypair, promotes it to primary, keeps old primary active for grace.</summary>
    Task<SigningKey> CreateNewKeyAsync();

    /// <summary>Full rotation: create new primary, retire keys expired > 30 days ago.</summary>
    Task RotateKeysAsync();

    /// <summary>Ensures at least one active primary key exists. Idempotent bootstrap call.</summary>
    Task EnsureBootstrapKeyAsync();

    // Legacy alias — returns primary key (same as GetPrimaryKeyAsync)
    Task<SigningKey> GetActiveKeyAsync();
}

public class KeyManagementService(
    DbContext context,
    ILogger<KeyManagementService> logger) : IKeyManagementService
{
    private readonly DbContext _context = context;
    private readonly ILogger<KeyManagementService> _logger = logger;

    private static readonly TimeSpan KeyLifetime    = TimeSpan.FromDays(90);
    private static readonly TimeSpan RetireAfter    = TimeSpan.FromDays(30); // after expiry

    public async Task<SigningKey> GetPrimaryKeyAsync()
    {
        var key = await _context.Set<SigningKey>()
            .Where(k => k.IsActive && k.IsPrimary && k.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefaultAsync();

        if (key is null)
        {
            _logger.LogWarning("No active primary signing key — bootstrapping");
            key = await CreateNewKeyAsync();
        }

        return key;
    }

    // Legacy alias
    public Task<SigningKey> GetActiveKeyAsync() => GetPrimaryKeyAsync();

    public async Task<List<SigningKey>> GetActiveKeysAsync()
    {
        // JWKS should include: primary + active non-primary (grace period for existing tokens)
        // Exclude keys retired > 24h ago so consumers have time to cache-bust
        var graceCutoff = DateTime.UtcNow.AddHours(-24);

        return await _context.Set<SigningKey>()
            .Where(k => k.IsActive ||
                       (k.RetiredAt.HasValue && k.RetiredAt.Value > graceCutoff))
            .OrderByDescending(k => k.IsPrimary)
            .ThenByDescending(k => k.CreatedAt)
            .ToListAsync();
    }

    public async Task<SigningKey> CreateNewKeyAsync()
    {
        // Atomically demote the current primary before inserting the new one
        await _context.Set<SigningKey>()
            .Where(k => k.IsPrimary)
            .ExecuteUpdateAsync(s => s.SetProperty(k => k.IsPrimary, false));

        using var rsa = RSA.Create(2048);
        var kid = GenerateKid();

        var signingKey = new SigningKey
        {
            Id          = Guid.NewGuid(),
            KeyId       = kid,
            Algorithm   = "RS256",
            PublicKey   = Convert.ToBase64String(rsa.ExportRSAPublicKey()),
            PrivateKey  = Convert.ToBase64String(rsa.ExportRSAPrivateKey()),
            IsActive    = true,
            IsPrimary   = true,
            CreatedAt   = DateTime.UtcNow,
            ActivatedAt = DateTime.UtcNow,
            ExpiresAt   = DateTime.UtcNow.Add(KeyLifetime),
        };

        _context.Set<SigningKey>().Add(signingKey);
        await _context.SaveChangesAsync();

        _logger.LogInformation("New primary signing key created: {Kid}", kid);
        return signingKey;
    }

    public async Task RotateKeysAsync()
    {
        var newKey = await CreateNewKeyAsync();

        // Retire keys whose expiry was more than RetireAfter ago
        var retireCutoff = DateTime.UtcNow - RetireAfter;
        var retired = await _context.Set<SigningKey>()
            .Where(k => k.IsActive && !k.IsPrimary && k.ExpiresAt < retireCutoff)
            .ExecuteUpdateAsync(s => s
                .SetProperty(k => k.IsActive, false)
                .SetProperty(k => k.RetiredAt, DateTime.UtcNow));

        _logger.LogInformation(
            "Key rotation complete. New primary: {Kid}. Retired: {Count} expired keys.",
            newKey.KeyId, retired);
    }

    public async Task EnsureBootstrapKeyAsync()
    {
        var hasActive = await _context.Set<SigningKey>()
            .AnyAsync(k => k.IsActive && k.IsPrimary && k.ExpiresAt > DateTime.UtcNow);

        if (!hasActive)
        {
            _logger.LogInformation("EnsureBootstrapKeyAsync: no active primary key — creating bootstrap key");
            await CreateNewKeyAsync();
        }
    }

    private static string GenerateKid() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(8))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
