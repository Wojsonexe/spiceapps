using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Enums;
using SpiceAuth.Infrastructure.Data;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.Tests.Services;

public abstract class ExternalAuthServiceTestBase : IDisposable
{
    protected readonly ApplicationDbContext Db;
    protected readonly ExternalAuthService Service;
    protected readonly Mock<ITokenService> MockTokenService;
    protected readonly Mock<UserManager<ApplicationUser>> MockUserManager;

    protected ExternalAuthServiceTestBase()
    {
        Db = new ApplicationDbContext(
            new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options);

        MockTokenService = new Mock<ITokenService>();

        var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
        MockUserManager  = new Mock<UserManager<ApplicationUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        MockTokenService
            .Setup(t => t.GenerateAccessTokenAsync(It.IsAny<TokenRequest>()))
            .ReturnsAsync("test-access-token");
        MockTokenService
            .Setup(t => t.GenerateRefreshTokenAsync(
                It.IsAny<Guid>(), It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<Guid?>()))
            .ReturnsAsync("test-refresh-token");

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:InternalClientId"] = "spiceapi-internal",
                ["App:FrontendUrl"]       = "https://app.test"
            })
            .Build();

        Service = new ExternalAuthService(
            Db,
            MockUserManager.Object,
            MockTokenService.Object,
            config,
            new Mock<ILogger<ExternalAuthService>>().Object);
    }

    // ── Seed helpers ──────────────────────────────────────────────────────────

    protected OAuthClient SeedInternalClient()
    {
        var client = new OAuthClient
        {
            Id                = Guid.NewGuid(),
            ClientId          = "spiceapi-internal",
            Name              = "Internal",
            ClientType        = ClientType.Confidential,
            IsActive          = true,
            RedirectUris      = "[]",
            AllowedScopes     = "[\"openid\"]",
            AllowedGrantTypes = "[\"password\"]",
            CreatedByUserId   = Guid.NewGuid()
        };
        Db.OAuthClients.Add(client);
        Db.SaveChanges();
        return client;
    }

    protected ApplicationUser SetupUser(Guid? id = null, string email = "test@example.com", string? passwordHash = null)
    {
        var user = new ApplicationUser
        {
            Id           = id ?? Guid.NewGuid(),
            Email        = email,
            UserName     = "testuser",
            PasswordHash = passwordHash
        };
        MockUserManager
            .Setup(um => um.FindByIdAsync(user.Id.ToString()))
            .ReturnsAsync(user);
        MockUserManager
            .Setup(um => um.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(["User"]);
        MockUserManager
            .Setup(um => um.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
        return user;
    }

    protected ExternalIdentity SeedExternalIdentity(
        Guid userId,
        string provider       = "discord",
        string providerUserId = "discord-123")
    {
        var identity = new ExternalIdentity
        {
            UserId         = userId,
            Provider       = provider,
            ProviderUserId = providerUserId,
            LinkedAt       = DateTime.UtcNow
        };
        Db.ExternalIdentities.Add(identity);
        Db.SaveChanges();
        return identity;
    }

    public void Dispose()
    {
        Db.Database.EnsureDeleted();
        Db.Dispose();
    }
}

public class ExternalAuthServiceTests : ExternalAuthServiceTestBase
{
    // ── Case 3a: known ExternalIdentity → log in as linked user ──────────────

    [Fact]
    public async Task Authenticate_Case3a_KnownDiscordId_ReturnsTokens()
    {
        var user = SetupUser();
        SeedExternalIdentity(user.Id, "discord", "discord-123");
        SeedInternalClient();

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-123", "user@example.com", "TestUser", null);

        Assert.True(result.Success);
        Assert.Equal("test-access-token", result.AccessToken);
        Assert.Equal("test-refresh-token", result.RefreshToken);
        Assert.False(result.WasLinked);
        Assert.Null(result.ErrorCode);
    }

    [Fact]
    public async Task Authenticate_Case3a_LinkedUserDeletedFromDb_ReturnsFail()
    {
        var userId = Guid.NewGuid();
        SeedExternalIdentity(userId, "discord", "discord-orphan");
        MockUserManager.Setup(um => um.FindByIdAsync(userId.ToString()))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-orphan", null, null, null);

        Assert.False(result.Success);
        Assert.Null(result.AccessToken);
    }

    // ── Case 3b: no ExternalIdentity, active session → link ──────────────────

    [Fact]
    public async Task Authenticate_Case3b_ActiveSession_LinksDiscordAndReturnsWasLinked()
    {
        var user = SetupUser();
        SeedInternalClient();

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-new", "user@example.com", "TestUser", "https://cdn.discord/avatar.png",
            emailVerified: false, authenticatedUserId: user.Id);

        Assert.True(result.Success);
        Assert.True(result.WasLinked);
        Assert.Equal("test-access-token", result.AccessToken);

        var identity = await Db.ExternalIdentities
            .FirstOrDefaultAsync(e => e.Provider == "discord" && e.ProviderUserId == "discord-new");
        Assert.NotNull(identity);
        Assert.Equal(user.Id, identity.UserId);
        Assert.Equal("https://cdn.discord/avatar.png", identity.AvatarUrl);
    }

    [Fact]
    public async Task Authenticate_Case3b_UserAlreadyHasDiscordLinked_ReturnsAlreadyLinked()
    {
        var user = SetupUser();
        SeedExternalIdentity(user.Id, "discord", "discord-old");

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-different", null, null, null,
            emailVerified: false, authenticatedUserId: user.Id);

        Assert.False(result.Success);
        Assert.Equal("already_linked", result.ErrorCode);
    }

    [Fact]
    public async Task Authenticate_Case3b_SessionUserNotFound_ReturnsFail()
    {
        var unknownId = Guid.NewGuid();
        MockUserManager.Setup(um => um.FindByIdAsync(unknownId.ToString()))
            .ReturnsAsync((ApplicationUser?)null);

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-new", null, null, null,
            emailVerified: false, authenticatedUserId: unknownId);

        Assert.False(result.Success);
        Assert.Null(result.ErrorCode);
    }

    // ── Case 3c: no session, verified email matches existing user → conflict ──

    [Fact]
    public async Task Authenticate_Case3c_VerifiedEmailMatchesExistingAccount_ReturnsEmailConflict()
    {
        var existingUser = new ApplicationUser
        {
            Id = Guid.NewGuid(), Email = "existing@example.com", UserName = "existing"
        };
        MockUserManager.Setup(um => um.FindByEmailAsync("existing@example.com"))
            .ReturnsAsync(existingUser);

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-new", "existing@example.com", "DiscordUser", null,
            emailVerified: true, authenticatedUserId: null);

        Assert.False(result.Success);
        Assert.Equal("email_conflict", result.ErrorCode);
    }

    [Fact]
    public async Task Authenticate_Case3c_UnverifiedEmail_SkipsEmailCheck_CreatesNewAccount()
    {
        // emailVerified=false → email conflict check skipped → new user created
        MockUserManager.Setup(um => um.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
        MockUserManager.Setup(um => um.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"))
            .ReturnsAsync(IdentityResult.Success);
        MockUserManager.Setup(um => um.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(["User"]);
        MockUserManager.Setup(um => um.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
        SeedInternalClient();

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-unverified", "existing@example.com", "DiscordUser", null,
            emailVerified: false, authenticatedUserId: null);

        Assert.True(result.Success);
        Assert.False(result.WasLinked);
    }

    // ── Case 3c: no session, no email match → provision new account ───────────

    [Fact]
    public async Task Authenticate_Case3c_NoEmailMatch_CreatesNewUserAndReturnsTokens()
    {
        MockUserManager.Setup(um => um.FindByEmailAsync(It.IsAny<string>()))
            .ReturnsAsync((ApplicationUser?)null);
        MockUserManager.Setup(um => um.CreateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
        MockUserManager.Setup(um => um.AddToRoleAsync(It.IsAny<ApplicationUser>(), "User"))
            .ReturnsAsync(IdentityResult.Success);
        MockUserManager.Setup(um => um.GetRolesAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(["User"]);
        MockUserManager.Setup(um => um.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
        SeedInternalClient();

        var result = await Service.AuthenticateExternalAsync(
            "discord", "discord-brand-new", "newuser@discord.com", "NewUser",
            "https://cdn.discordapp.com/avatars/123/abc.png",
            emailVerified: true, authenticatedUserId: null);

        Assert.True(result.Success);
        Assert.Equal("test-access-token", result.AccessToken);
        Assert.False(result.WasLinked);

        var identity = await Db.ExternalIdentities
            .FirstOrDefaultAsync(e => e.ProviderUserId == "discord-brand-new");
        Assert.NotNull(identity);
        Assert.Equal("https://cdn.discordapp.com/avatars/123/abc.png", identity.AvatarUrl);
    }

    // ── UnlinkExternalProviderAsync ───────────────────────────────────────────

    [Fact]
    public async Task Unlink_UserHasPassword_RemovesExternalIdentity()
    {
        var user = SetupUser(passwordHash: "hashed-password");
        SeedExternalIdentity(user.Id, "discord", "discord-123");

        var ok = await Service.UnlinkExternalProviderAsync(user.Id, "discord");

        Assert.True(ok);
        Assert.False(await Db.ExternalIdentities
            .AnyAsync(e => e.UserId == user.Id && e.Provider == "discord"));
    }

    [Fact]
    public async Task Unlink_NoPasswordSingleProvider_ReturnsFalse()
    {
        var user = SetupUser(passwordHash: null); // no password
        SeedExternalIdentity(user.Id, "discord", "discord-123");

        var ok = await Service.UnlinkExternalProviderAsync(user.Id, "discord");

        Assert.False(ok);
        Assert.True(await Db.ExternalIdentities
            .AnyAsync(e => e.UserId == user.Id && e.Provider == "discord"));
    }

    [Fact]
    public async Task Unlink_NoPasswordMultipleProviders_Succeeds()
    {
        var user = SetupUser(passwordHash: null);
        SeedExternalIdentity(user.Id, "discord", "discord-123");
        SeedExternalIdentity(user.Id, "google", "google-456");

        var ok = await Service.UnlinkExternalProviderAsync(user.Id, "discord");

        Assert.True(ok);
        Assert.False(await Db.ExternalIdentities
            .AnyAsync(e => e.UserId == user.Id && e.Provider == "discord"));
        Assert.True(await Db.ExternalIdentities
            .AnyAsync(e => e.UserId == user.Id && e.Provider == "google"));
    }

    // ── GetLinkedProvidersAsync ───────────────────────────────────────────────

    [Fact]
    public async Task GetLinkedProviders_ReturnsAllLinkedWithAvatarUrl()
    {
        var userId = Guid.NewGuid();
        Db.ExternalIdentities.Add(new ExternalIdentity
        {
            UserId         = userId,
            Provider       = "discord",
            ProviderUserId = "discord-123",
            AvatarUrl      = "https://cdn.discordapp.com/avatars/123/abc.png",
            LinkedAt       = DateTime.UtcNow
        });
        Db.SaveChanges();

        var providers = await Service.GetLinkedProvidersAsync(userId);

        Assert.Single(providers);
        Assert.Equal("discord", providers[0].Provider);
        Assert.Equal("https://cdn.discordapp.com/avatars/123/abc.png", providers[0].AvatarUrl);
    }
}
