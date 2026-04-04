using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SpiceAuth.Application.Services.Email;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Tests.Services;

public class IdentityServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<UserManager<ApplicationUser>> _userManagerMock;
    private readonly Mock<IEmailService> _emailServiceMock;
    private readonly IdentityService _identityService;

    public IdentityServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);

        var userStoreMock = new Mock<IUserStore<ApplicationUser>>();
        _userManagerMock = new Mock<UserManager<ApplicationUser>>(
            userStoreMock.Object, null!, null!, null!, null!, null!, null!, null!, null!);

        var tokenServiceMock = new Mock<ITokenService>();
        var loggerMock = new Mock<ILogger<IdentityService>>();
        
        _emailServiceMock = new Mock<IEmailService>();
        _identityService = new IdentityService(
            _context,
            _userManagerMock.Object,
            tokenServiceMock.Object,
            _emailServiceMock.Object,
            loggerMock.Object);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void SetupUserManagerCreate(IdentityResult? result = null)
    {
        _userManagerMock
            .Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .ReturnsAsync(result ?? IdentityResult.Success);
    }

    private void SetupUserManagerUpdate()
    {
        _userManagerMock
            .Setup(x => x.UpdateAsync(It.IsAny<ApplicationUser>()))
            .ReturnsAsync(IdentityResult.Success);
    }
    
    private async Task<Guid> CreateTestUserAsync(string email = "test@example.com", string username = "testuser")
    {
        SetupUserManagerCreate();
        var response = await _identityService.CreateUserAsync(
            email, username, "Password123!", "Test", "User");
        Assert.True(response.Success);
        return response.UserId!.Value;
    }

    // ── CreateUserAsync ───────────────────────────────────────────────────────

    [Fact]
    public async Task CreateUserAsync_ShouldReturnSuccess_WhenValidData()
    {
        SetupUserManagerCreate();

        var result = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "Password123!", "Test", "User");

        Assert.True(result.Success);
        Assert.NotNull(result.UserId);
        Assert.Null(result.Message);
    }

    [Fact]
    public async Task CreateUserAsync_ShouldReturnFailure_WhenEmailExists()
    {
        await CreateTestUserAsync("existing@example.com", "user1");

        SetupUserManagerCreate();

        var result = await _identityService.CreateUserAsync(
            "existing@example.com", "user2", "Pass123!", "Test", "User");

        Assert.False(result.Success);
        Assert.Equal("Email is already in use", result.Message);
    }

    [Fact]
    public async Task CreateUserAsync_ShouldReturnFailure_WhenWeakPassword()
    {
        SetupUserManagerCreate();

        var result = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "weak", "Test", "User");

        Assert.False(result.Success);
        Assert.NotNull(result.Message);
    }


    [Fact]
    public async Task GenerateEmailVerificationTokenAsync_ShouldCreateToken()
    {
        var userId = await CreateTestUserAsync();

        _emailServiceMock
            .Setup(x => x.SendEmailVerificationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        await _identityService.GenerateEmailVerificationTokenAsync(userId, "127.0.0.1", "TestAgent");

        var dbToken = await _context.Set<EmailVerificationToken>()
            .FirstOrDefaultAsync(t => t.UserId == userId);

        Assert.NotNull(dbToken);
        Assert.Equal(userId, dbToken.UserId);
        Assert.False(dbToken.IsUsed);
        Assert.True(dbToken.ExpiresAt > DateTime.UtcNow);

        _emailServiceMock.Verify(
            x => x.SendEmailVerificationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Once);
    }

    // ── VerifyEmailAsync ──────────────────────────────────────────────────────

    [Fact]
    public async Task VerifyEmailAsync_ShouldVerifyEmail_WhenValidToken()
    {
        SetupUserManagerUpdate();
        var userId = await CreateTestUserAsync();

        _emailServiceMock
            .Setup(x => x.SendEmailVerificationAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        _emailServiceMock
            .Setup(x => x.SendWelcomeEmailAsync(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        await _identityService.GenerateEmailVerificationTokenAsync(userId, "127.0.0.1", "TestAgent");

        var dbToken = await _context.Set<EmailVerificationToken>()
            .FirstOrDefaultAsync(t => t.UserId == userId && !t.IsUsed);

        Assert.NotNull(dbToken);

        var result = await _identityService.VerifyEmailAsync(dbToken.Token);

        Assert.True(result);

        _emailServiceMock.Verify(
            x => x.SendWelcomeEmailAsync(It.IsAny<string>(), It.IsAny<string>()),
            Times.Once);
    }

    [Fact]
    public async Task VerifyEmailAsync_ShouldReturnFalse_WhenInvalidToken()
    {
        var result = await _identityService.VerifyEmailAsync("invalid-token-xyz");
        Assert.False(result);
    }

    // ── Account Lockout ───────────────────────────────────────────────────────

    [Fact]
    public async Task RecordLoginAttemptAsync_ShouldLockAccount_AfterMaxFailedAttempts()
    {
        SetupUserManagerUpdate();
        var userId = await CreateTestUserAsync();

        await _identityService.ActivateUserAsync(userId);

        var user = await _identityService.GetUserByIdAsync(userId);

        for (int i = 0; i < 5; i++)
        {
            await _identityService.RecordLoginAttemptAsync(
                user!.Email!, false, "127.0.0.1", "TestAgent", "Invalid password");
        }

        var isLocked = await _identityService.IsAccountLockedAsync(user!.Email!);
        Assert.True(isLocked);

        var updatedUser = await _identityService.GetUserByIdAsync(userId);
        Assert.True(updatedUser!.IsSuspended);
        Assert.NotNull(updatedUser.SuspendedUntil);
    }

    [Fact]
    public async Task GetFailedLoginAttemptsAsync_ShouldReturnCorrectCount()
    {
        var email = "test@example.com";

        await _identityService.RecordLoginAttemptAsync(email, false, "127.0.0.1", "TestAgent");
        await _identityService.RecordLoginAttemptAsync(email, false, "127.0.0.1", "TestAgent");
        await _identityService.RecordLoginAttemptAsync(email, true,  "127.0.0.1", "TestAgent");
        await _identityService.RecordLoginAttemptAsync(email, false, "127.0.0.1", "TestAgent");

        var failedCount = await _identityService.GetFailedLoginAttemptsAsync(
            email, TimeSpan.FromMinutes(15));

        Assert.Equal(3, failedCount);
    }

    public void Dispose()
    {
        _context.Database.EnsureDeleted();
        _context.Dispose();
    }
}
