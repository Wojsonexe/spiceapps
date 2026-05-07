using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Enums;
using SpiceAuth.Infrastructure.Data;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.Tests.Integration;

/// <summary>
/// Verifies that the ExecuteUpdateAsync(WHERE !IsUsed) pattern provides
/// correct atomic single-use enforcement under concurrent access.
///
/// Uses SQLite (not InMemory) to exercise real transactional behavior.
/// Two parallel tasks attempt to exchange the same authorization code;
/// exactly one must succeed and one must detect the replay.
/// </summary>
public class ConcurrentRedemptionTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"spiceauth-test-{Guid.NewGuid():N}.db");
    private readonly Guid _userId   = Guid.NewGuid();
    private readonly Guid _clientId;
    private readonly string _code;

    public ConcurrentRedemptionTests()
    {
        _clientId = Guid.NewGuid();
        _code     = GenerateCode();

        // Seed database synchronously in constructor
        var options = BuildOptions();
        using var db = new ApplicationDbContext(options);
        db.Database.EnsureCreated();
        SeedData(db).GetAwaiter().GetResult();
    }

    [Fact]
    public async Task ConcurrentExchange_ExactlyOneSucceeds_OtherDetectsReplay()
    {
        // Two goroutines racing to exchange the same code
        var task1 = Task.Run(AttemptExchangeAsync);
        var task2 = Task.Run(AttemptExchangeAsync);

        var results = await Task.WhenAll(task1, task2);

        foreach (var r in results)
            if (r.Error != null)
                throw new Exception("Unexpected error in concurrent exchange", r.Error);

        var successes = results.Count(r => r.Succeeded);
        var replays   = results.Count(r => r.WasReplay);

        Assert.Equal(1, successes);
        Assert.Equal(1, replays);
    }

    private async Task<(bool Succeeded, bool WasReplay, Exception? Error)> AttemptExchangeAsync()
    {
        var options = BuildOptions();
        await using var db = new ApplicationDbContext(options);
        var service = BuildService(db);

        try
        {
            await service.ExchangeAuthorizationCodeAsync(
                _code, _clientId, "https://app.test/callback", null);
            return (true, false, null);
        }
        catch (AuthorizationCodeReplayException)
        {
            return (false, true, null);
        }
        catch (Exception ex)
        {
            return (false, false, ex);
        }
    }

    private DbContextOptions<ApplicationDbContext> BuildOptions() =>
        new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite($"Data Source={_dbPath}")
            .Options;

    private async Task SeedData(ApplicationDbContext db)
    {
        db.Set<OAuthClient>().Add(new OAuthClient
        {
            Id                = _clientId,
            ClientId          = "concurrent-test-client",
            Name              = "Concurrent Test",
            ClientType        = ClientType.Public,
            RedirectUris      = """["https://app.test/callback"]""",
            AllowedScopes     = """["openid"]""",
            AllowedGrantTypes = """["authorization_code"]""",
            IsActive          = true,
            CreatedByUserId   = Guid.NewGuid()
        });

        db.Set<AuthorizationCode>().Add(new AuthorizationCode
        {
            Id          = Guid.NewGuid(),
            Code        = _code,
            ClientId    = _clientId,
            UserId      = _userId,
            RedirectUri = "https://app.test/callback",
            Scope       = "openid",
            IsUsed      = false,
            ExpiresAt   = DateTime.UtcNow.AddMinutes(10),
            CreatedAt   = DateTime.UtcNow
        });

        await db.SaveChangesAsync();
    }

    private OAuthService BuildService(ApplicationDbContext db)
    {
        var mockToken = new Mock<ITokenService>();
        mockToken
            .Setup(t => t.GenerateAccessTokenAsync(It.IsAny<TokenRequest>()))
            .ReturnsAsync("access-token");
        mockToken
            .Setup(t => t.GenerateRefreshTokenAsync(
                It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<Guid?>()))
            .ReturnsAsync(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

        var user          = new ApplicationUser { Id = _userId, Email = "t@t.com", UserName = "t" };
        var userStoreMock  = new Mock<IUserStore<ApplicationUser>>();
        var userManager   = new Mock<UserManager<ApplicationUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);
        userManager.Setup(m => m.FindByIdAsync(_userId.ToString())).ReturnsAsync(user);
        userManager.Setup(m => m.GetRolesAsync(It.IsAny<ApplicationUser>())).ReturnsAsync(["User"]);

        var uriSanitizer = new Mock<IUriSanitizer>();
        uriSanitizer.Setup(s => s.ValidateAsync(It.IsAny<string>()))
                    .ReturnsAsync(UriValidationResult.Ok());

        return new OAuthService(
            db,
            new Mock<IIdentityStore>().Object,
            mockToken.Object,
            new Mock<ILogger<OAuthService>>().Object,
            userManager.Object,
            new Mock<IFederationService>().Object,
            new Mock<ISecurityEventService>().Object,
            new PkceService(new Mock<ILogger<PkceService>>().Object),
            uriSanitizer.Object);
    }

    private static string GenerateCode() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .Replace("+", "-").Replace("/", "_").Replace("=", "");

    public void Dispose()
    {
        // Clear pooled SQLite connections so the file handle is released before deletion.
        SqliteConnection.ClearAllPools();
        if (File.Exists(_dbPath)) File.Delete(_dbPath);
    }
}
