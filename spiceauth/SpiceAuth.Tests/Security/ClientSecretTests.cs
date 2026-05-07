using SpiceAuth.Application.Exceptions;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Tests.Helpers;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Verifies multi-version client secret authentication.
/// Tests both the legacy OAuthClient.ClientSecretHash path
/// and the new versioned ClientSecrets table (spc_prefix.body format).
/// </summary>
public class ClientSecretTests : OAuthServiceTestBase
{
    // ── Legacy path (OAuthClient.ClientSecretHash) ────────────────────────────

    [Fact]
    public async Task Validate_LegacySecret_CorrectPassword_Succeeds()
    {
        var client = SeedClient();   // seeded with BCrypt("test-secret", 4)

        // Should not throw
        await Service.ValidateClientCredentialsAsync(client.ClientId, "test-secret");
    }

    [Fact]
    public async Task Validate_LegacySecret_WrongPassword_ThrowsOAuthException()
    {
        var client = SeedClient();

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ValidateClientCredentialsAsync(client.ClientId, "wrong-secret"));

        Assert.Equal("invalid_client", ex.Error);
    }

    [Fact]
    public async Task Validate_PublicClient_NoSecretRequired_Succeeds()
    {
        var client = SeedClient(type: Core.Enums.ClientType.Public, noSecret: true);

        // Public clients don't require a secret
        await Service.ValidateClientCredentialsAsync(client.ClientId, null);
    }

    [Fact]
    public async Task Validate_ConfidentialClient_MissingSecret_ThrowsOAuthException()
    {
        var client = SeedClient();  // Confidential

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ValidateClientCredentialsAsync(client.ClientId, null));

        Assert.Equal("invalid_client", ex.Error);
    }

    // ── Versioned secret path (spc_prefix.body) ───────────────────────────────

    [Fact]
    public async Task Validate_VersionedSecret_CorrectSecret_Succeeds()
    {
        var client = SeedClient(noSecret: true);  // no legacy hash

        const string prefix    = "spc_testprefix1234";
        const string rawSecret = prefix + ".testbodybodybody123456789012";
        var secretHash         = BCrypt.Net.BCrypt.HashPassword(rawSecret, 4);

        Db.Set<ClientSecret>().Add(new ClientSecret
        {
            Id               = Guid.NewGuid(),
            ClientInternalId = client.Id,
            Prefix           = prefix,
            SecretHash       = secretHash,
            IsActive         = true,
            CreatedAt        = DateTime.UtcNow
        });
        await Db.SaveChangesAsync();

        // Should not throw
        await Service.ValidateClientCredentialsAsync(client.ClientId, rawSecret);
    }

    [Fact]
    public async Task Validate_VersionedSecret_WrongBody_ThrowsOAuthException()
    {
        var client = SeedClient(noSecret: true);

        const string prefix     = "spc_testprefix5678";
        const string rawSecret  = prefix + ".correctbody9876543210123456";
        var secretHash          = BCrypt.Net.BCrypt.HashPassword(rawSecret, 4);

        Db.Set<ClientSecret>().Add(new ClientSecret
        {
            Id               = Guid.NewGuid(),
            ClientInternalId = client.Id,
            Prefix           = prefix,
            SecretHash       = secretHash,
            IsActive         = true,
            CreatedAt        = DateTime.UtcNow
        });
        await Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ValidateClientCredentialsAsync(client.ClientId,
                prefix + ".wrongbodywrongbodywrongbodyxx"));

        Assert.Equal("invalid_client", ex.Error);
    }

    [Fact]
    public async Task Validate_VersionedSecret_RevokedSecret_ThrowsOAuthException()
    {
        var client = SeedClient(noSecret: true);

        const string prefix    = "spc_revokedprefix00";
        const string rawSecret = prefix + ".revokebody12345678901234567";
        var secretHash         = BCrypt.Net.BCrypt.HashPassword(rawSecret, 4);

        Db.Set<ClientSecret>().Add(new ClientSecret
        {
            Id               = Guid.NewGuid(),
            ClientInternalId = client.Id,
            Prefix           = prefix,
            SecretHash       = secretHash,
            IsActive         = false,    // revoked
            RevokedAt        = DateTime.UtcNow.AddHours(-1),
            CreatedAt        = DateTime.UtcNow.AddDays(-10)
        });
        await Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ValidateClientCredentialsAsync(client.ClientId, rawSecret));

        Assert.Equal("invalid_client", ex.Error);
    }

    [Fact]
    public async Task Validate_VersionedSecret_ExpiredSecret_ThrowsOAuthException()
    {
        var client = SeedClient(noSecret: true);

        const string prefix    = "spc_expiredprefix12";
        const string rawSecret = prefix + ".expiredbody12345678901234xx";
        var secretHash         = BCrypt.Net.BCrypt.HashPassword(rawSecret, 4);

        Db.Set<ClientSecret>().Add(new ClientSecret
        {
            Id               = Guid.NewGuid(),
            ClientInternalId = client.Id,
            Prefix           = prefix,
            SecretHash       = secretHash,
            IsActive         = true,
            ExpiresAt        = DateTime.UtcNow.AddHours(-1),   // expired
            CreatedAt        = DateTime.UtcNow.AddDays(-30)
        });
        await Db.SaveChangesAsync();

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ValidateClientCredentialsAsync(client.ClientId, rawSecret));

        Assert.Equal("invalid_client", ex.Error);
    }

    [Fact]
    public async Task Validate_VersionedSecret_UpdatesLastUsedAt()
    {
        var client = SeedClient(noSecret: true);

        const string prefix    = "spc_lastupdprefix12";
        const string rawSecret = prefix + ".trackingbody12345678901234x";
        var secretHash         = BCrypt.Net.BCrypt.HashPassword(rawSecret, 4);
        var secretId           = Guid.NewGuid();

        Db.Set<ClientSecret>().Add(new ClientSecret
        {
            Id               = secretId,
            ClientInternalId = client.Id,
            Prefix           = prefix,
            SecretHash       = secretHash,
            IsActive         = true,
            CreatedAt        = DateTime.UtcNow,
            LastUsedAt       = null   // not yet used
        });
        await Db.SaveChangesAsync();

        await Service.ValidateClientCredentialsAsync(client.ClientId, rawSecret);

        // Reload to get the updated value
        Db.ChangeTracker.Clear();
        var stored = await Db.Set<ClientSecret>().FindAsync(secretId);

        Assert.NotNull(stored!.LastUsedAt);
        Assert.True(stored.LastUsedAt > DateTime.UtcNow.AddMinutes(-1));
    }

    [Fact]
    public async Task Validate_MultipleActiveSecrets_CorrectPrefixMatches()
    {
        var client = SeedClient(noSecret: true);

        const string prefix1    = "spc_secretalpha001";
        const string rawSecret1 = prefix1 + ".body-alpha-123456789012345678";
        const string prefix2    = "spc_secretbeta0002";
        const string rawSecret2 = prefix2 + ".body-beta-01234567890123456789";

        Db.Set<ClientSecret>().AddRange(
            new ClientSecret
            {
                Id               = Guid.NewGuid(),
                ClientInternalId = client.Id,
                Prefix           = prefix1,
                SecretHash       = BCrypt.Net.BCrypt.HashPassword(rawSecret1, 4),
                IsActive         = true,
                CreatedAt        = DateTime.UtcNow
            },
            new ClientSecret
            {
                Id               = Guid.NewGuid(),
                ClientInternalId = client.Id,
                Prefix           = prefix2,
                SecretHash       = BCrypt.Net.BCrypt.HashPassword(rawSecret2, 4),
                IsActive         = true,
                CreatedAt        = DateTime.UtcNow
            });
        await Db.SaveChangesAsync();

        // Both secrets must work independently
        await Service.ValidateClientCredentialsAsync(client.ClientId, rawSecret1);
        await Service.ValidateClientCredentialsAsync(client.ClientId, rawSecret2);
    }
}
