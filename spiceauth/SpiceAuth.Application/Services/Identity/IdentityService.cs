using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Email;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Application.Services.Identity;

public sealed class IdentityService : IIdentityService
{
    private readonly DbContext _context;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<IdentityService> _logger;
    private readonly IEmailService _emailService;

    private const int MaxFailedLoginAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan FailedLoginWindow = TimeSpan.FromMinutes(15);

    public IdentityService(
        DbContext context,
        IPasswordHasher passwordHasher,
        IEmailService emailService,
        ILogger<IdentityService> logger)
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _logger = logger;
        _emailService = emailService;
    }
    
    public async Task<LoginResponse> AuthenticateAsync(string email, string password, string? ipAddress = null, string? userAgent = null)
    {
        ipAddress ??= "unknown";
        userAgent ??= "unknown";
        
        // Check if account is locked
        if (await IsAccountLockedAsync(email))
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Account locked");
            
            _logger.LogWarning("Login attempt for locked account: {Email}", email);
            return new LoginResponse
            {
                Success = false,
                Message = "Account is temporarily locked due to too many failed login attempts. Please try again later or reset your password."
            };
        }

        var user = await GetUserByEmailAsync(email);

        if (user == null)
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "User not found");
            
            _logger.LogWarning("Login attempt for non-existent user: {Email}", email);
            return new LoginResponse
            {
                Success = false,
                Message = "Invalid email or password"
            };
        }

        if (!user.IsActive)
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Account not active");
            
            _logger.LogWarning("Login attempt for inactive user: {UserId}", user.Id);
            return new LoginResponse
            {
                Success = false,
                Message = "Account is not active. Please wait for approval or verify your email."
            };
        }

        if (user.IsSuspended)
        {
            if (user.SuspendedUntil.HasValue && user.SuspendedUntil.Value > DateTime.UtcNow)
            {
                await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Account suspended");
                
                _logger.LogWarning("Login attempt for suspended user: {UserId}", user.Id);
                return new LoginResponse
                {
                    Success = false,
                    Message = $"Account is suspended until {user.SuspendedUntil.Value:yyyy-MM-dd HH:mm}"
                };
            }

            // Auto-unsuspend if suspension period expired
            user.IsSuspended = false;
            user.SuspendedUntil = null;
            await _context.SaveChangesAsync();
        }

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "No password set");
            
            _logger.LogWarning("Login attempt with password for user without password: {UserId}", user.Id);
            return new LoginResponse
            {
                Success = false,
                Message = "Please login using your connected account (Discord, Google, etc.)"
            };
        }

        if (!_passwordHasher.VerifyPassword(password, user.PasswordHash))
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Invalid password");
            
            _logger.LogWarning("Failed login attempt for user: {UserId}", user.Id);
            
            var failedAttempts = await GetFailedLoginAttemptsAsync(email, FailedLoginWindow);
            var attemptsLeft = MaxFailedLoginAttempts - failedAttempts;
            
            if (attemptsLeft <= 2 && attemptsLeft > 0)
            {
                return new LoginResponse
                {
                    Success = false,
                    Message = $"Invalid email or password. {attemptsLeft} attempt(s) remaining before account lockout."
                };
            }
            
            return new LoginResponse
            {
                Success = false,
                Message = "Invalid email or password"
            };
        }

        // Check MFA
        var mfaSettings = await _context.Set<Core.Entities.Security.MfaSettings>()
            .FirstOrDefaultAsync(m => m.UserId == user.Id);

        if (mfaSettings?.IsEnabled == true)
        {
            _logger.LogInformation("User {UserId} requires MFA", user.Id);
            return new LoginResponse
            {
                Success = false,
                RequiresMfa = true,
                MfaToken = "TODO_GENERATE_MFA_TOKEN",
                Message = "MFA required"
            };
        }

        // Successful login
        user.LastLoginAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        
        await RecordLoginAttemptAsync(email, true, ipAddress, userAgent);

        _logger.LogInformation("User {UserId} logged in successfully", user.Id);

        return new LoginResponse
        {
            Success = true,
            User = MapToUserDto(user)
        };
    }
    
    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        return await _context.Set<User>()
            .Include(u => u.ExternalIdentities)
            .Include(u => u.MfaSettings)
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    public async Task<User?> GetUserByEmailAsync(string email)
    {
        return await _context.Set<User>()
            .Include(u => u.ExternalIdentities)
            .Include(u => u.MfaSettings)
            .FirstOrDefaultAsync(u => u.Email.ToLower() == email.ToLower());
    }

    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        return await _context.Set<User>()
            .Include(u => u.ExternalIdentities)
            .Include(u => u.MfaSettings)
            .FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());
    }

    public async Task<User> CreateUserAsync(
        string email, 
        string username, 
        string? password, 
        string? firstName, 
        string? lastName)
    {
        if (!await IsEmailAvailableAsync(email))
            throw new InvalidOperationException("Email is already in use");

        if (!await IsUsernameAvailableAsync(username))
            throw new InvalidOperationException("Username is already in use");

        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email.ToLower(),
            Username = username,
            FirstName = firstName,
            LastName = lastName,
            EmailConfirmed = false,
            IsActive = false,
            IsSuspended = false,
            CreatedAt = DateTime.UtcNow
        };

        if (!string.IsNullOrWhiteSpace(password))
        {
            user.PasswordHash = _passwordHasher.HashPassword(password);
        }

        _context.Set<User>().Add(user);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Created user {UserId} with email {Email}", user.Id, user.Email);

        return user;
    }

    public async Task<bool> UpdateUserAsync(
        Guid userId, 
        string? firstName, 
        string? lastName, 
        string? profilePictureUrl)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
            return false;

        user.FirstName = firstName;
        user.LastName = lastName;
        user.ProfilePictureUrl = profilePictureUrl;
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("Updated user {UserId}", userId);
        return true;
    }

    public async Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
            return false;

        if (string.IsNullOrEmpty(user.PasswordHash))
            throw new InvalidOperationException("User does not have a password set");

        if (!_passwordHasher.VerifyPassword(currentPassword, user.PasswordHash))
        {
            _logger.LogWarning("Failed password change attempt for user {UserId}", userId);
            return false;
        }

        user.PasswordHash = _passwordHasher.HashPassword(newPassword);
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} changed password", userId);
        return true;
    }

    public async Task<bool> SuspendUserAsync(Guid userId, DateTime? suspendedUntil, string reason)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
            return false;

        user.IsSuspended = true;
        user.SuspendedUntil = suspendedUntil;
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogWarning("User {UserId} suspended until {SuspendedUntil}. Reason: {Reason}", 
            userId, suspendedUntil, reason);

        return true;
    }

    public async Task<bool> ActivateUserAsync(Guid userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
            return false;

        user.IsActive = true;
        user.IsSuspended = false;
        user.SuspendedUntil = null;
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} activated", userId);
        return true;
    }

    public async Task<bool> IsEmailAvailableAsync(string email)
    {
        return !await _context.Set<User>().AnyAsync(u => u.Email.ToLower() == email.ToLower());
    }

    public async Task<bool> IsUsernameAvailableAsync(string username)
    {
        return !await _context.Set<User>().AnyAsync(u => u.Username.ToLower() == username.ToLower());
    }

    public async Task<bool> ValidatePasswordAsync(Guid userId, string password)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null || string.IsNullOrEmpty(user.PasswordHash))
            return false;

        return _passwordHasher.VerifyPassword(password, user.PasswordHash);
    }

    private static UserDto MapToUserDto(User user)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            Username = user.Username,
            FirstName = user.FirstName,
            LastName = user.LastName,
            ProfilePictureUrl = user.ProfilePictureUrl,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        };
    }

    #region Email Verification

    public async Task<string> GenerateEmailVerificationTokenAsync(Guid userId, string ipAddress, string userAgent)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
            throw new InvalidOperationException("User not found");

        if (user.EmailConfirmed)
            throw new InvalidOperationException("Email is already verified");

        // Invalidate any existing tokens
        var existingTokens = await _context.Set<EmailVerificationToken>()
            .Where(t => t.UserId == userId && !t.IsUsed)
            .ToListAsync();

        foreach (var token in existingTokens)
        {
            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
        }

        // Generate new token
        var tokenValue = GenerateSecureToken();
        var verificationToken = new EmailVerificationToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Token = tokenValue,
            Email = user.Email,
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            IsUsed = false,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        };

        _context.Set<EmailVerificationToken>().Add(verificationToken);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Email verification token generated for user {UserId}", userId);

        // Send email
        await _emailService.SendEmailVerificationAsync(user.Email, user.Username, tokenValue);

        return tokenValue;
    }

    public async Task<bool> VerifyEmailAsync(string token)
    {
        var verificationToken = await _context.Set<EmailVerificationToken>()
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed);

        if (verificationToken == null)
        {
            _logger.LogWarning("Email verification attempted with invalid token");
            return false;
        }

        if (verificationToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Email verification attempted with expired token for user {UserId}", 
                verificationToken.UserId);
            return false;
        }

        var user = verificationToken.User;
        user.EmailConfirmed = true;
        user.UpdatedAt = DateTime.UtcNow;

        verificationToken.IsUsed = true;
        verificationToken.UsedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("Email verified for user {UserId}", user.Id);

        // Send welcome email
        await _emailService.SendWelcomeEmailAsync(user.Email, user.Username);

        return true;
    }

    public async Task<bool> ResendEmailVerificationAsync(Guid userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
            return false;

        if (user.EmailConfirmed)
        {
            _logger.LogWarning("Attempted to resend verification for already verified user {UserId}", userId);
            return false;
        }

        await GenerateEmailVerificationTokenAsync(userId, "system", "resend");
        return true;
    }

    #endregion

    #region Password Reset

    public async Task<string?> GeneratePasswordResetTokenAsync(string email, string ipAddress, string userAgent)
    {
        var user = await GetUserByEmailAsync(email);
        if (user == null)
        {
            // Don't reveal that user doesn't exist
            _logger.LogWarning("Password reset requested for non-existent email: {Email}", email);
            return null;
        }

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            _logger.LogWarning("Password reset requested for user without password: {UserId}", user.Id);
            return null;
        }

        // Invalidate existing tokens
        var existingTokens = await _context.Set<PasswordResetToken>()
            .Where(t => t.UserId == user.Id && !t.IsUsed)
            .ToListAsync();

        foreach (var token in existingTokens)
        {
            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
        }

        // Generate new token
        var tokenValue = GenerateSecureToken();
        var resetToken = new PasswordResetToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Token = tokenValue,
            Email = user.Email,
            ExpiresAt = DateTime.UtcNow.AddHours(1), // 1 hour expiry
            IsUsed = false,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        };

        _context.Set<PasswordResetToken>().Add(resetToken);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Password reset token generated for user {UserId}", user.Id);

        // Send email
        await _emailService.SendPasswordResetAsync(user.Email, user.Username, tokenValue);

        return tokenValue;
    }

    public async Task<bool> ResetPasswordAsync(string token, string newPassword)
    {
        var resetToken = await _context.Set<PasswordResetToken>()
            .Include(t => t.User)
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed);

        if (resetToken == null)
        {
            _logger.LogWarning("Password reset attempted with invalid token");
            return false;
        }

        if (resetToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Password reset attempted with expired token for user {UserId}", 
                resetToken.UserId);
            return false;
        }

        var user = resetToken.User;
        user.PasswordHash = _passwordHasher.HashPassword(newPassword);
        user.UpdatedAt = DateTime.UtcNow;

        resetToken.IsUsed = true;
        resetToken.UsedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation("Password reset successful for user {UserId}", user.Id);

        return true;
    }

    public async Task<bool> ValidatePasswordResetTokenAsync(string token)
    {
        var resetToken = await _context.Set<PasswordResetToken>()
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed);

        if (resetToken == null)
            return false;

        return resetToken.ExpiresAt >= DateTime.UtcNow;
    }

    #endregion

    #region Account Lockout

    public async Task RecordLoginAttemptAsync(
        string email, 
        bool isSuccessful, 
        string ipAddress, 
        string? userAgent, 
        string? failureReason = null)
    {
        var user = await GetUserByEmailAsync(email);

        var attempt = new LoginAttempt
        {
            Id = Guid.NewGuid(),
            UserId = user?.Id,
            Email = email.ToLower(),
            IpAddress = ipAddress,
            UserAgent = userAgent,
            IsSuccessful = isSuccessful,
            AttemptedAt = DateTime.UtcNow,
            FailureReason = failureReason,
            CreatedAt = DateTime.UtcNow
        };

        _context.Set<LoginAttempt>().Add(attempt);
        await _context.SaveChangesAsync();

        // Check if account should be locked
        if (!isSuccessful && user != null)
        {
            var failedAttempts = await GetFailedLoginAttemptsAsync(email, FailedLoginWindow);
            
            if (failedAttempts >= MaxFailedLoginAttempts)
            {
                await SuspendUserAsync(
                    user.Id, 
                    DateTime.UtcNow.Add(LockoutDuration),
                    $"Too many failed login attempts ({failedAttempts})");
                
                _logger.LogWarning(
                    "User {UserId} locked out due to {FailedAttempts} failed login attempts", 
                    user.Id, 
                    failedAttempts);
            }
        }
    }

    public async Task<bool> IsAccountLockedAsync(string email)
    {
        var user = await GetUserByEmailAsync(email);
        if (user == null)
            return false;

        if (!user.IsSuspended)
            return false;

        if (user.SuspendedUntil.HasValue && user.SuspendedUntil.Value <= DateTime.UtcNow)
        {
            // Unlock automatically if suspension period expired
            user.IsSuspended = false;
            user.SuspendedUntil = null;
            await _context.SaveChangesAsync();
            return false;
        }

        return true;
    }

    public async Task<int> GetFailedLoginAttemptsAsync(string email, TimeSpan timeWindow)
    {
        var cutoff = DateTime.UtcNow.Subtract(timeWindow);
        
        return await _context.Set<LoginAttempt>()
            .CountAsync(a => 
                a.Email.ToLower() == email.ToLower() && 
                !a.IsSuccessful && 
                a.AttemptedAt >= cutoff);
    }

    #endregion

    #region Helper Methods

    private static string GenerateSecureToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }

    #endregion
}