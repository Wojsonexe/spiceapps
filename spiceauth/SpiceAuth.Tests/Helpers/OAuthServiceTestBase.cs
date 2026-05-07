using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
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

namespace SpiceAuth.Tests.Helpers;

/// <summary>
/// Shared base for OAuthService unit tests.
/// Uses InMemory EF Core (EF8 supports ExecuteUpdate/ExecuteDelete on InMemory).
/// </summary>
public abstract class OAuthServiceTestBase : IDisposable
{
    protected readonly ApplicationDbContext Db;
    protected readonly OAuthService Service;
    protected readonly Mock<ITokenService> MockTokenService;
    protected readonly Mock<IFederationService> MockFederation;
    protected readonly Mock<ISecurityEventService> MockSecurityEvents;
    protected readonly Mock<UserManager<ApplicationUser>> MockUserManager;

    protected OAuthServiceTestBase()
    {
        Db = BuildDb(Guid.NewGuid().ToString());

        MockTokenService   = new Mock<ITokenService>();
        MockFederation     = new Mock<IFederationService>();
        MockSecurityEvents = new Mock<ISecurityEventService>();

        var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
        MockUserManager   = new Mock<UserManager<ApplicationUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        MockTokenService
            .Setup(t => t.GenerateAccessTokenAsync(It.IsAny<TokenRequest>()))
            .ReturnsAsync("test-access-token");

        MockTokenService
            .Setup(t => t.GenerateRefreshTokenAsync(
                It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<Guid?>()))
            .ReturnsAsync("raw-new-refresh-token");

        MockFederation
            .Setup(f => f.RevokeAllUserSessionsAsync(It.IsAny<Guid>()))
            .Returns(Task.CompletedTask);

        Service = BuildService(Db, MockUserManager.Object);
    }

    // ── Factory helpers ───────────────────────────────────────────────────────

    protected static ApplicationDbContext BuildDb(string dbName) =>
        new(new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(dbName)
            .Options);

    protected OAuthService BuildService(
        ApplicationDbContext db,
        UserManager<ApplicationUser> userManager,
        IUriSanitizer? uriSanitizer = null)
    {
        // Default sanitizer accepts everything — override in SSRF-specific tests
        var sanitizer = uriSanitizer ?? CreatePermissiveUriSanitizer();

        return new OAuthService(
            db,
            new Mock<IIdentityStore>().Object,
            MockTokenService.Object,
            new Mock<ILogger<OAuthService>>().Object,
            userManager,
            MockFederation.Object,
            MockSecurityEvents.Object,
            new PkceService(new Mock<ILogger<PkceService>>().Object),
            sanitizer);
    }

    protected static IUriSanitizer CreatePermissiveUriSanitizer()
    {
        var mock = new Mock<IUriSanitizer>();
        mock.Setup(s => s.ValidateAsync(It.IsAny<string>()))
            .ReturnsAsync(UriValidationResult.Ok());
        return mock.Object;
    }

    protected static IUriSanitizer CreateRejectingUriSanitizer(string error = "SSRF blocked")
    {
        var mock = new Mock<IUriSanitizer>();
        mock.Setup(s => s.ValidateAsync(It.IsAny<string>()))
            .ReturnsAsync(UriValidationResult.Fail(error));
        return mock.Object;
    }

    // ── Seed helpers ──────────────────────────────────────────────────────────

    protected OAuthClient SeedClient(
        string clientId = "test-client",
        ClientType type = ClientType.Confidential,
        bool noSecret   = false)
    {
        var client = new OAuthClient
        {
            Id                = Guid.NewGuid(),
            ClientId          = clientId,
            Name              = "Test Client",
            ClientType        = type,
            RedirectUris      = """["https://app.test/callback"]""",
            AllowedScopes     = """["openid","profile"]""",
            AllowedGrantTypes = """["authorization_code","refresh_token"]""",
            IsActive          = true,
            ClientSecretHash  = noSecret
                ? null
                : BCrypt.Net.BCrypt.HashPassword("test-secret", 4),
            CreatedByUserId   = Guid.NewGuid()
        };
        Db.Set<OAuthClient>().Add(client);
        Db.SaveChanges();
        return client;
    }

    protected ApplicationUser SetupUser(Guid? id = null)
    {
        var user = new ApplicationUser
        {
            Id       = id ?? Guid.NewGuid(),
            Email    = "test@example.com",
            UserName = "testuser"
        };
        MockUserManager
            .Setup(um => um.FindByIdAsync(user.Id.ToString()))
            .ReturnsAsync(user);
        MockUserManager
            .Setup(um => um.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(["User"]);
        return user;
    }

    protected AuthorizationCode SeedAuthCode(
        OAuthClient client,
        ApplicationUser user,
        string? codeChallenge       = null,
        string? codeChallengeMethod = null,
        bool expired                = false)
    {
        var code = new AuthorizationCode
        {
            Id                  = Guid.NewGuid(),
            Code                = GenerateCode(),
            ClientId            = client.Id,
            UserId              = user.Id,
            RedirectUri         = "https://app.test/callback",
            Scope               = "openid profile",
            CodeChallenge       = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod ?? (codeChallenge != null ? "S256" : null),
            IsUsed              = false,
            ExpiresAt           = expired
                ? DateTime.UtcNow.AddMinutes(-5)
                : DateTime.UtcNow.AddMinutes(10),
            CreatedAt           = DateTime.UtcNow
        };
        Db.Set<AuthorizationCode>().Add(code);
        Db.SaveChanges();
        return code;
    }

    protected RefreshToken SeedRefreshToken(
        OAuthClient client,
        ApplicationUser user,
        string rawToken,
        bool isUsed    = false,
        bool isRevoked = false,
        bool expired   = false,
        Guid? familyId = null)
    {
        var token = new RefreshToken
        {
            Id        = Guid.NewGuid(),
            TokenHash = HashToken(rawToken),
            ClientId  = client.Id,
            UserId    = user.Id,
            Scope     = "openid profile",
            IsUsed    = isUsed,
            IsRevoked = isRevoked,
            FamilyId  = familyId ?? Guid.NewGuid(),
            ExpiresAt = expired
                ? DateTime.UtcNow.AddDays(-1)
                : DateTime.UtcNow.AddDays(7),
            CreatedAt = DateTime.UtcNow
        };
        Db.Set<RefreshToken>().Add(token);
        Db.SaveChanges();
        return token;
    }

    // ── PKCE helper ───────────────────────────────────────────────────────────

    protected static string ComputeS256Challenge(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private static string HashToken(string token)
    {
        using var sha = SHA256.Create();
        return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(token)));
    }

    protected static string GenerateCode() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))
            .Replace("+", "-").Replace("/", "_").Replace("=", "");

    public void Dispose()
    {
        Db.Database.EnsureDeleted();
        Db.Dispose();
    }
}
