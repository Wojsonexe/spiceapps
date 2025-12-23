using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Services;

public interface IKeyManagementService
{
    Task<SigningKey> GetActiveKeyAsync();
    Task<List<SigningKey>> GetActiveKeysAsync();
    Task<SigningKey> CreateNewKeyAsync();
    Task RotateKeysAsync();
}

public class KeyManagementService(
    DbContext context,
    ILogger<KeyManagementService> logger) : IKeyManagementService
{
    private readonly DbContext _context = context;
    private readonly ILogger<KeyManagementService> _logger = logger;

    public async Task<SigningKey> GetActiveKeyAsync()
    {
        var activeKey = await _context.Set<SigningKey>()
            .Where(k => k.IsActive)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefaultAsync();

        if (activeKey == null)
        {
            _logger.LogWarning("No active signing key found, creating new one");
            activeKey = await CreateNewKeyAsync();
        }

        return activeKey;
    }

    public async Task<List<SigningKey>> GetActiveKeysAsync()
    {
        // Return current active key + previous key (for rotation grace period)
        return await _context.Set<SigningKey>()
            .Where(k => k.IsActive || (k.RetiredAt.HasValue && k.RetiredAt.Value > DateTime.UtcNow.AddHours(-24)))
            .OrderByDescending(k => k.CreatedAt)
            .Take(2)
            .ToListAsync();
    }

    public async Task<SigningKey> CreateNewKeyAsync()
    {
        using var rsa = RSA.Create(2048);
        
        var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
        var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
        
        var keyId = Guid.NewGuid().ToString("N")[..16]; // Short kid

        var signingKey = new SigningKey
        {
            Id = Guid.NewGuid(),
            KeyId = keyId,
            Algorithm = "RS256",
            PublicKey = publicKey,
            PrivateKey = privateKey, // TODO: Encrypt at rest
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            ActivatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(90),
        };

        _context.Set<SigningKey>().Add(signingKey);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Created new signing key: {KeyId}", keyId);

        return signingKey;
    }

    public async Task RotateKeysAsync()
    {
        var activeKeys = await _context.Set<SigningKey>()
            .Where(k => k.IsActive)
            .ToListAsync();

        // Mark old keys as retired
        foreach (var key in activeKeys)
        {
            key.IsActive = false;
            key.RetiredAt = DateTime.UtcNow;
        }

        // Create new key
        await CreateNewKeyAsync();
        await _context.SaveChangesAsync();

        _logger.LogInformation("Rotated signing keys, {Count} keys retired", activeKeys.Count);
    }
}