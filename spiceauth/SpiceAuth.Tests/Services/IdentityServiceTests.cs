using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using SpiceAuth.Application.Services.Email;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Tests.Services;

public class IdentityServiceTests : IDisposable
{
    private readonly ApplicationDbContext _context;
    private readonly Mock<IPasswordHasher> _passwordHasherMock;
    private readonly Mock<IEmailService> _emailServiceMock;
    private readonly Mock<ILogger<IdentityService>> _loggerMock;
    private readonly IdentityService _identityService;

    public IdentityServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new ApplicationDbContext(options);
        _passwordHasherMock = new Mock<IPasswordHasher>();
        _emailServiceMock = new Mock<IEmailService>();
        _loggerMock = new Mock<ILogger<IdentityService>>();

        _identityService = new IdentityService(
            _context,
            _passwordHasherMock.Object,
            _emailServiceMock.Object,
            _loggerMock.Object);
    }

    [Fact]
    public async Task CreateUserAsync_ShouldCreateUser_WhenValidData()
    {
        // Arrange
        var email = "test@example.com";
        var username = "testuser";
        var password = "Password123!";

        _passwordHasherMock
            .Setup(x => x.HashPassword(password))
            .Returns("hashed_password");

        // Act
        var user = await _identityService.CreateUserAsync(
            email, username, password, "Test", "User");

        // Assert
        Assert.NotNull(user);
        Assert.Equal(email.ToLower(), user.Email);
        Assert.Equal(username, user.Username);
        Assert.Equal("hashed_password", user.PasswordHash);
        Assert.False(user.EmailConfirmed);
        Assert.False(user.IsActive);
    }

    [Fact]
    public async Task CreateUserAsync_ShouldThrowException_WhenEmailExists()
    {
        // Arrange
        var email = "existing@example.com";
        await _identityService.CreateUserAsync(
            email, "user1", "pass", null, null);

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _identityService.CreateUserAsync(
                email, "user2", "pass", null, null));
    }

    [Fact]
    public async Task GenerateEmailVerificationTokenAsync_ShouldCreateToken()
    {
        // Arrange
        var user = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "pass", null, null);

        // Act
        var token = await _identityService.GenerateEmailVerificationTokenAsync(
            user.Id, "127.0.0.1", "TestAgent");

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);

        var dbToken = await _context.Set<EmailVerificationToken>()
            .FirstOrDefaultAsync(t => t.Token == token);

        Assert.NotNull(dbToken);
        Assert.Equal(user.Id, dbToken.UserId);
        Assert.False(dbToken.IsUsed);
        Assert.True(dbToken.ExpiresAt > DateTime.UtcNow);

        _emailServiceMock.Verify(
            x => x.SendEmailVerificationAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                token),
            Times.Once);
    }

    [Fact]
    public async Task VerifyEmailAsync_ShouldVerifyEmail_WhenValidToken()
    {
        // Arrange
        var user = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "pass", null, null);

        var token = await _identityService.GenerateEmailVerificationTokenAsync(
            user.Id, "127.0.0.1", "TestAgent");

        // Act
        var result = await _identityService.VerifyEmailAsync(token);

        // Assert
        Assert.True(result);

        var updatedUser = await _identityService.GetUserByIdAsync(user.Id);
        Assert.True(updatedUser!.EmailConfirmed);

        _emailServiceMock.Verify(
            x => x.SendWelcomeEmailAsync(
                It.IsAny<string>(),
                It.IsAny<string>()),
            Times.Once);
    }

    [Fact]
    public async Task VerifyEmailAsync_ShouldFail_WhenTokenExpired()
    {
        // Arrange
        var user = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "pass", null, null);

        var tokenValue = Guid.NewGuid().ToString();
        var expiredToken = new EmailVerificationToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Token = tokenValue,
            Email = user.Email,
            ExpiresAt = DateTime.UtcNow.AddHours(-1), // Expired
            IsUsed = false,
            CreatedAt = DateTime.UtcNow.AddHours(-2)
        };

        _context.Set<EmailVerificationToken>().Add(expiredToken);
        await _context.SaveChangesAsync();

        // Act
        var result = await _identityService.VerifyEmailAsync(tokenValue);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task GeneratePasswordResetTokenAsync_ShouldCreateToken()
    {
        // Arrange
        _passwordHasherMock.Setup(x => x.HashPassword(It.IsAny<string>()))
            .Returns("hashed");

        var user = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "pass", null, null);

        // Act
        var token = await _identityService.GeneratePasswordResetTokenAsync(
            user.Email, "127.0.0.1", "TestAgent");

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);

        var dbToken = await _context.Set<PasswordResetToken>()
            .FirstOrDefaultAsync(t => t.Token == token);

        Assert.NotNull(dbToken);
        Assert.Equal(user.Id, dbToken.UserId);
        Assert.False(dbToken.IsUsed);

        _emailServiceMock.Verify(
            x => x.SendPasswordResetAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                token),
            Times.Once);
    }

    [Fact]
    public async Task ResetPasswordAsync_ShouldResetPassword_WhenValidToken()
    {
        // Arrange
        _passwordHasherMock.Setup(x => x.HashPassword(It.IsAny<string>()))
            .Returns("hashed");

        var user = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "oldpass", null, null);

        var token = await _identityService.GeneratePasswordResetTokenAsync(
            user.Email, "127.0.0.1", "TestAgent");

        var newPassword = "NewPassword123!";
        _passwordHasherMock.Setup(x => x.HashPassword(newPassword))
            .Returns("new_hashed");

        // Act
        var result = await _identityService.ResetPasswordAsync(token!, newPassword);

        // Assert
        Assert.True(result);

        var updatedUser = await _identityService.GetUserByIdAsync(user.Id);
        Assert.Equal("new_hashed", updatedUser!.PasswordHash);
    }

    [Fact]
    public async Task RecordLoginAttemptAsync_ShouldLockAccount_AfterMaxFailedAttempts()
    {
        // Arrange
        _passwordHasherMock.Setup(x => x.HashPassword(It.IsAny<string>()))
            .Returns("hashed");

        var user = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "pass", null, null);

        await _identityService.ActivateUserAsync(user.Id);

        // Act - Record 5 failed attempts
        for (int i = 0; i < 5; i++)
        {
            await _identityService.RecordLoginAttemptAsync(
                user.Email, false, "127.0.0.1", "TestAgent", "Invalid password");
        }

        // Assert
        var isLocked = await _identityService.IsAccountLockedAsync(user.Email);
        Assert.True(isLocked);

        var updatedUser = await _identityService.GetUserByIdAsync(user.Id);
        Assert.True(updatedUser!.IsSuspended);
        Assert.NotNull(updatedUser.SuspendedUntil);
    }

    [Fact]
    public async Task AuthenticateAsync_ShouldFail_WhenAccountLocked()
    {
        // Arrange
        _passwordHasherMock.Setup(x => x.HashPassword(It.IsAny<string>()))
            .Returns("hashed");
        _passwordHasherMock.Setup(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(true);

        var user = await _identityService.CreateUserAsync(
            "test@example.com", "testuser", "pass", null, null);

        await _identityService.ActivateUserAsync(user.Id);

        // Lock the account
        await _identityService.SuspendUserAsync(
            user.Id, DateTime.UtcNow.AddMinutes(15), "Too many failed attempts");

        // Act
        var response = await _identityService.AuthenticateAsync(
            user.Email, "pass", "127.0.0.1", "TestAgent");

        // Assert
        Assert.False(response.Success);
        Assert.Contains("locked", response.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetFailedLoginAttemptsAsync_ShouldReturnCorrectCount()
    {
        // Arrange
        var email = "test@example.com";

        // Record some attempts
        await _identityService.RecordLoginAttemptAsync(
            email, false, "127.0.0.1", "TestAgent");
        await _identityService.RecordLoginAttemptAsync(
            email, false, "127.0.0.1", "TestAgent");
        await _identityService.RecordLoginAttemptAsync(
            email, true, "127.0.0.1", "TestAgent");
        await _identityService.RecordLoginAttemptAsync(
            email, false, "127.0.0.1", "TestAgent");

        // Act
        var failedCount = await _identityService.GetFailedLoginAttemptsAsync(
            email, TimeSpan.FromMinutes(15));

        // Assert
        Assert.Equal(3, failedCount);
    }

    public void Dispose()
    {
        _context.Database.EnsureDeleted();
        _context.Dispose();
    }
}