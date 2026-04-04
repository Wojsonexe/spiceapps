using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Common;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Email;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Application.Services.Identity;

public sealed class IdentityService(
    DbContext context,
    UserManager<ApplicationUser> userManager,
    ITokenService tokenService,
    IEmailService emailService,
    ILogger<IdentityService> logger) : IIdentityService
{
    private const int MaxFailedLoginAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan FailedLoginWindow = TimeSpan.FromMinutes(15);

    public async Task<LoginResponse> AuthenticateAsync(string email, string password, string ipAddress, string userAgent)
    {
        if (await IsAccountLockedAsync(email))
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Account locked");
            return new LoginResponse { Success = false, Message = "Account is temporarily locked." };
        }

        var user = await GetUserByEmailAsync(email);
        if (user == null)
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "User not found");
            return new LoginResponse { Success = false, Message = "Invalid email or password" };
        }

        if (!user.EmailConfirmed)
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Email not verified");
            return new LoginResponse { Success = false, RequiresEmailVerification = true, Message = "Please verify your email address." };
        }

        if (!user.IsActive)
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Account not active");
            return new LoginResponse { Success = false, Message = "Account is not active." };
        }

        if (user.IsSuspended)
        {
            if (user.SuspendedUntil.HasValue && user.SuspendedUntil.Value > DateTime.UtcNow)
            {
                await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Account suspended");
                return new LoginResponse { Success = false, Message = $"Account suspended until {user.SuspendedUntil.Value:yyyy-MM-dd HH:mm}" };
            }

            user.IsSuspended = false;
            user.SuspendedUntil = null;
            user.UpdatedAt = DateTime.UtcNow;
            await userManager.UpdateAsync(user);
        }

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "No password set");
            return new LoginResponse { Success = false, Message = "Please login using your connected account." };
        }

        var isPasswordValid = await userManager.CheckPasswordAsync(user, password);
        if (!isPasswordValid)
        {
            await RecordLoginAttemptAsync(email, false, ipAddress, userAgent, "Invalid password");
            var failedAttempts = await GetFailedLoginAttemptsAsync(email, FailedLoginWindow);
            var attemptsLeft = MaxFailedLoginAttempts - failedAttempts;
            return new LoginResponse
            {
                Success = false,
                Message = attemptsLeft is > 0 and <= 2
                    ? $"Invalid email or password. {attemptsLeft} attempt(s) remaining."
                    : "Invalid email or password"
            };
        }

        var mfaSettings = await context.Set<Core.Entities.Security.MfaSettings>()
            .FirstOrDefaultAsync(m => m.UserId == user.Id);

        if (mfaSettings?.IsEnabled == true)
        {
            return new LoginResponse
            {
                Success = false,
                RequiresMfa = true,
                MfaToken = "TODO_GENERATE_MFA_TOKEN",
                Message = "MFA required"
            };
        }

        var activeClients = await context.Set<OAuthClient>()
            .Where(c => c.IsActive)
            .ToListAsync();

        var defaultClient = activeClients.FirstOrDefault(c => c.AllowedGrantTypes.Contains("password"))
                            ?? activeClients.FirstOrDefault();

        if (defaultClient == null)
        {
            logger.LogError("No active OAuth client found.");
            return new LoginResponse { Success = false, Message = "Authentication service misconfigured." };
        }

        var userRoles = await userManager.GetRolesAsync(user);
        var tokenRequest = new TokenRequest
        {
            UserId = user.Id,
            ClientId = defaultClient.Id,
            Scope = "openid profile email",
            OrganizationId = null,
            Roles = userRoles.ToList(),
            Nonce = null
        };

        var accessToken = await tokenService.GenerateAccessTokenAsync(tokenRequest);
        var refreshToken = await tokenService.GenerateRefreshTokenAsync(user.Id, defaultClient.Id, "openid profile email");

        user.LastLoginAt = DateTime.UtcNow;
        user.UpdatedAt = DateTime.UtcNow;
        await userManager.UpdateAsync(user);
        await RecordLoginAttemptAsync(email, true, ipAddress, userAgent);

        logger.LogInformation("User {UserId} logged in successfully", user.Id);

        return new LoginResponse
        {
            Success = true,
            Message = "Login successful",
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            UserId = user.Id,
            Email = user.Email,
            Username = user.UserName
        };
    }

    public async Task<ApplicationUser?> GetUserByIdAsync(Guid userId)
        => await context.Set<ApplicationUser>()
            .Include(u => u.ExternalIdentities)
            .Include(u => u.MfaSettings)
            .FirstOrDefaultAsync(u => u.Id == userId);

    public async Task<ApplicationUser?> GetUserByEmailAsync(string email)
        => await context.Set<ApplicationUser>()
            .Include(u => u.ExternalIdentities)
            .Include(u => u.MfaSettings)
            .FirstOrDefaultAsync(u => u.Email != null && u.Email.ToLower() == email.ToLower());

    public async Task<ApplicationUser?> GetUserByUsernameAsync(string username)
        => await context.Set<ApplicationUser>()
            .Include(u => u.ExternalIdentities)
            .Include(u => u.MfaSettings)
            .FirstOrDefaultAsync(u => u.UserName != null && u.UserName.ToLower() == username.ToLower());

    public async Task<RegisterResponse> CreateUserAsync(
        string email,
        string username,
        string password,
        string firstName,
        string lastName)
    {
        if (!await IsEmailAvailableAsync(email))
            return new RegisterResponse { Success = false, Message = "Email is already in use" };

        if (!await IsUsernameAvailableAsync(username))
            return new RegisterResponse { Success = false, Message = "Username is already in use" };

        if (!IsPasswordStrong(password))
            return new RegisterResponse { Success = false, Message = "Password must be at least 8 characters and contain uppercase, lowercase, digit, and special character" };

        var user = new ApplicationUser
        {
            Email = email.ToLower(),
            UserName = username,
            FirstName = firstName,
            LastName = lastName,
            EmailConfirmed = false,
            IsActive = false,
            CreatedAt = DateTime.UtcNow
        };

        var result = await userManager.CreateAsync(user, password);

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            return new RegisterResponse { Success = false, Message = errors };
        }

        logger.LogInformation("Created user {UserId} with email {Email}", user.Id, email);
        return new RegisterResponse { Success = true, UserId = user.Id };
    }

    public async Task<bool> UpdateUserAsync(Guid userId, string? firstName, string? lastName, string? profilePictureUrl)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null) return false;

        user.FirstName = firstName;
        user.LastName = lastName;
        user.ProfilePictureUrl = profilePictureUrl;
        user.UpdatedAt = DateTime.UtcNow;

        var result = await userManager.UpdateAsync(user);
        logger.LogInformation("Updated user {UserId}", userId);
        return result.Succeeded;
    }

    public async Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null) return false;

        if (string.IsNullOrEmpty(user.PasswordHash))
            throw new InvalidOperationException("User does not have a password set");

        if (!await userManager.CheckPasswordAsync(user, currentPassword))
        {
            logger.LogWarning("Failed password change attempt for user {UserId}", userId);
            return false;
        }

        if (!IsPasswordStrong(newPassword))
            throw new InvalidOperationException("Password too weak");

        var result = await userManager.ChangePasswordAsync(user, currentPassword, newPassword);
        if (!result.Succeeded) return false;

        user.UpdatedAt = DateTime.UtcNow;
        await userManager.UpdateAsync(user);
        logger.LogInformation("User {UserId} changed password", userId);
        return true;
    }

    public async Task<bool> SuspendUserAsync(Guid userId, DateTime? suspendedUntil, string reason)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null) return false;

        user.IsSuspended = true;
        user.SuspendedUntil = suspendedUntil;
        user.UpdatedAt = DateTime.UtcNow;

        var result = await userManager.UpdateAsync(user);
        logger.LogWarning("User {UserId} suspended until {SuspendedUntil}. Reason: {Reason}", userId, suspendedUntil, reason);
        return result.Succeeded;
    }

    public async Task<bool> ActivateUserAsync(Guid userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null) return false;

        user.IsActive = true;
        user.IsSuspended = false;
        user.SuspendedUntil = null;
        user.UpdatedAt = DateTime.UtcNow;

        var result = await userManager.UpdateAsync(user);
        logger.LogInformation("User {UserId} activated", userId);
        return result.Succeeded;
    }

    public async Task<bool> IsEmailAvailableAsync(string email)
        => !await context.Set<ApplicationUser>().AnyAsync(u => u.Email != null && u.Email.ToLower() == email.ToLower());

    public async Task<bool> IsUsernameAvailableAsync(string username)
        => !await context.Set<ApplicationUser>().AnyAsync(u => u.UserName != null && u.UserName.ToLower() == username.ToLower());

    public async Task<bool> ValidatePasswordAsync(Guid userId, string password)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null || string.IsNullOrEmpty(user.PasswordHash)) return false;
        return await userManager.CheckPasswordAsync(user, password);
    }

    public async Task<OperationResult> UpdateUserProfileAsync(Guid userId, string? firstName, string? lastName, int department, DateOnly? birthDay)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user == null)
            return new OperationResult { Success = false, Message = "User not found" };

        if (firstName != null) user.FirstName = firstName;
        if (lastName != null) user.LastName = lastName;
        user.Department = department;
        user.BirthDay = birthDay;

        var result = await userManager.UpdateAsync(user);

        return new OperationResult
        {
            Success = result.Succeeded,
            Message = result.Succeeded ? "Profile updated" : "Update failed"
        };
    }

    public async Task<UserProfileResult> GetUserProfileAsync(Guid userId)
    {
        try
        {
            var user = await userManager.FindByIdAsync(userId.ToString());
            if (user == null)
                return new UserProfileResult { Success = false, Message = "User not found" };

            return new UserProfileResult
            {
                Success = true,
                Data = new UserProfileDto
                {
                    Id = user.Id,
                    Email = user.Email ?? "",
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Department = user.Department,
                    IsApproved = user.IsApproved,
                    BirthDay = user.BirthDay
                }
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get user profile for {UserId}", userId);
            return new UserProfileResult { Success = false, Message = "Internal server error" };
        }
    }
    
    public async Task<bool> LinkDiscordAsync(Guid userId, string discordId, string discordUsername)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user == null) return false;

        user.DiscordId = discordId;
        user.DiscordUsername = discordUsername;
        user.UpdatedAt = DateTime.UtcNow;

        var result = await userManager.UpdateAsync(user);
        return result.Succeeded;
    }

    #region Email Verification

    public async Task GenerateEmailVerificationTokenAsync(Guid userId, string ipAddress, string userAgent)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null) throw new InvalidOperationException("User not found");
        if (user.EmailConfirmed) throw new InvalidOperationException("Email is already verified");

        var recentTokens = await context.Set<EmailVerificationToken>()
            .Where(t => t.UserId == userId && t.CreatedAt >= DateTime.UtcNow.AddHours(-1))
            .CountAsync();

        if (recentTokens >= 3)
        {
            logger.LogWarning("Email verification rate limit exceeded for user {UserId}", userId);
            throw new InvalidOperationException("Too many verification emails sent. Please try again later.");
        }

        var existingTokens = await context.Set<EmailVerificationToken>()
            .Where(t => t.UserId == userId && !t.IsUsed)
            .ToListAsync();

        foreach (var token in existingTokens)
        {
            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
        }

        var tokenValue = GenerateSecureToken();
        context.Set<EmailVerificationToken>().Add(new EmailVerificationToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Token = tokenValue,
            Email = user.Email!,
            ExpiresAt = DateTime.UtcNow.AddHours(24),
            IsUsed = false,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });

        await context.SaveChangesAsync();
        logger.LogInformation("Email verification token generated for user {UserId}", userId);
        await emailService.SendEmailVerificationAsync(user.Email!, user.UserName!, tokenValue);
    }

    public async Task<bool> VerifyEmailAsync(string token)
    {
        var verificationToken = await context.Set<EmailVerificationToken>()
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed);

        if (verificationToken == null || verificationToken.ExpiresAt < DateTime.UtcNow)
            return false;

        var user = await GetUserByIdAsync(verificationToken.UserId);
        if (user == null) return false;

        user.EmailConfirmed = true;
        user.UpdatedAt = DateTime.UtcNow;
        verificationToken.IsUsed = true;
        verificationToken.UsedAt = DateTime.UtcNow;

        await userManager.UpdateAsync(user);
        await context.SaveChangesAsync();

        logger.LogInformation("Email verified for user {UserId}", user.Id);
        await emailService.SendWelcomeEmailAsync(user.Email!, user.UserName!);
        return true;
    }

    public async Task<bool> ResendEmailVerificationAsync(Guid userId)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null || user.EmailConfirmed) return false;

        await GenerateEmailVerificationTokenAsync(userId, "system", "resend");
        return true;
    }

    #endregion

    #region Password Reset

    public async Task<string?> GeneratePasswordResetTokenAsync(string email, string ipAddress, string userAgent)
    {
        var user = await GetUserByEmailAsync(email);
        if (user == null || string.IsNullOrEmpty(user.PasswordHash)) return null;

        var recentTokens = await context.Set<PasswordResetToken>()
            .Where(t => t.UserId == user.Id && t.CreatedAt >= DateTime.UtcNow.AddHours(-1))
            .CountAsync();

        if (recentTokens >= 3) return null;

        var existingTokens = await context.Set<PasswordResetToken>()
            .Where(t => t.UserId == user.Id && !t.IsUsed)
            .ToListAsync();

        foreach (var token in existingTokens)
        {
            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
        }

        var tokenValue = GenerateSecureToken();
        context.Set<PasswordResetToken>().Add(new PasswordResetToken
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            Token = tokenValue,
            Email = user.Email!,
            ExpiresAt = DateTime.UtcNow.AddHours(1),
            IsUsed = false,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            CreatedAt = DateTime.UtcNow
        });

        await context.SaveChangesAsync();
        await emailService.SendPasswordResetAsync(user.Email!, user.UserName!, tokenValue);
        return tokenValue;
    }

    public async Task<bool> ResetPasswordAsync(string token, string newPassword)
    {
        var resetToken = await context.Set<PasswordResetToken>()
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed);

        if (resetToken == null || resetToken.ExpiresAt < DateTime.UtcNow || !IsPasswordStrong(newPassword))
            return false;

        var user = await GetUserByIdAsync(resetToken.UserId);
        if (user == null) return false;

        var resetPasswordToken = await userManager.GeneratePasswordResetTokenAsync(user);
        var result = await userManager.ResetPasswordAsync(user, resetPasswordToken, newPassword);
        if (!result.Succeeded) return false;

        user.UpdatedAt = DateTime.UtcNow;
        await userManager.UpdateAsync(user);

        resetToken.IsUsed = true;
        resetToken.UsedAt = DateTime.UtcNow;
        await context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> ValidatePasswordResetTokenAsync(string token)
    {
        var resetToken = await context.Set<PasswordResetToken>()
            .FirstOrDefaultAsync(t => t.Token == token && !t.IsUsed);
        return resetToken != null && resetToken.ExpiresAt >= DateTime.UtcNow;
    }

    #endregion

    #region Account Lockout

    public async Task RecordLoginAttemptAsync(string email, bool isSuccessful, string ipAddress, string? userAgent, string? failureReason = null)
    {
        var user = await GetUserByEmailAsync(email);

        context.Set<LoginAttempt>().Add(new LoginAttempt
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
        });

        await context.SaveChangesAsync();

        if (!isSuccessful && user != null)
        {
            var failedAttempts = await GetFailedLoginAttemptsAsync(email, FailedLoginWindow);
            if (failedAttempts >= MaxFailedLoginAttempts)
            {
                await SuspendUserAsync(user.Id, DateTime.UtcNow.Add(LockoutDuration), $"Too many failed login attempts ({failedAttempts})");
                logger.LogWarning("User {UserId} locked out due to {FailedAttempts} failed login attempts", user.Id, failedAttempts);
            }
        }
    }

    public async Task<bool> IsAccountLockedAsync(string email)
    {
        var user = await GetUserByEmailAsync(email);
        if (user == null || !user.IsSuspended) return false;

        if (user.SuspendedUntil.HasValue && user.SuspendedUntil.Value <= DateTime.UtcNow)
        {
            user.IsSuspended = false;
            user.SuspendedUntil = null;
            user.UpdatedAt = DateTime.UtcNow;
            await userManager.UpdateAsync(user);
            return false;
        }

        return true;
    }

    public async Task<int> GetFailedLoginAttemptsAsync(string email, TimeSpan timeWindow)
    {
        var cutoff = DateTime.UtcNow.Subtract(timeWindow);
        return await context.Set<LoginAttempt>()
            .CountAsync(a => a.Email.ToLower() == email.ToLower() && !a.IsSuccessful && a.AttemptedAt >= cutoff);
    }

    #endregion

    #region MFA

    public Task<LoginResponse> ValidateMfaTokenAsync(string mfaToken)
        => Task.FromResult(new LoginResponse { Success = false, Message = "MFA not yet implemented" });

    public Task<LoginResponse> CompleteMfaLoginAsync(string mfaToken, string code, string ipAddress, string userAgent)
        => Task.FromResult(new LoginResponse { Success = false, Message = "MFA not yet implemented" });
    
    public async Task<ApplicationUser?> GetUserByDiscordIdAsync(string discordId)
        => await context.Set<ApplicationUser>()
            .FirstOrDefaultAsync(u => u.DiscordId == discordId);

    #endregion

    #region Tokens

    public async Task<LoginResponse> RefreshTokenAsync(string refreshToken)
    {
        using var sha256 = SHA256.Create();
        var tokenHash = Convert.ToBase64String(
            sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(refreshToken)));

        var stored = await context.Set<RefreshToken>()
            .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && !t.IsRevoked && !t.IsUsed);

        if (stored == null || stored.ExpiresAt < DateTime.UtcNow)
            return new LoginResponse { Success = false, Message = "Invalid or expired refresh token" };

        var user = await userManager.FindByIdAsync(stored.UserId.ToString());
        if (user == null || !user.IsActive)
            return new LoginResponse { Success = false, Message = "User not found or inactive" };

        stored.IsRevoked = true;
        stored.IsUsed = true;

        var userRoles = await userManager.GetRolesAsync(user);
        var tokenRequest = new TokenRequest
        {
            UserId = user.Id,
            ClientId = stored.ClientId,
            Scope = stored.Scope,
            Roles = userRoles.ToList()
        };

        var newAccessToken = await tokenService.GenerateAccessTokenAsync(tokenRequest);
        var newRefreshToken = await tokenService.GenerateRefreshTokenAsync(user.Id, stored.ClientId, stored.Scope);

        user.LastLoginAt = DateTime.UtcNow;
        user.UpdatedAt = DateTime.UtcNow;
        await userManager.UpdateAsync(user);
        await context.SaveChangesAsync();

        return new LoginResponse
        {
            Success = true,
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            UserId = user.Id,
            Email = user.Email,
            Username = user.UserName
        };
    }

    public Task RevokeRefreshTokenAsync(string userId)
        => Task.CompletedTask;

    #endregion

    #region Cleanup

    public async Task CleanupExpiredTokensAsync()
    {
        var cutoff = DateTime.UtcNow.AddDays(-7);

        var expiredEmailTokens = await context.Set<EmailVerificationToken>()
            .Where(t => t.ExpiresAt < cutoff || (t.IsUsed && t.UsedAt < cutoff))
            .ToListAsync();

        var expiredPasswordTokens = await context.Set<PasswordResetToken>()
            .Where(t => t.ExpiresAt < cutoff || (t.IsUsed && t.UsedAt < cutoff))
            .ToListAsync();

        var oldLoginAttempts = await context.Set<LoginAttempt>()
            .Where(a => a.AttemptedAt < cutoff)
            .ToListAsync();

        context.Set<EmailVerificationToken>().RemoveRange(expiredEmailTokens);
        context.Set<PasswordResetToken>().RemoveRange(expiredPasswordTokens);
        context.Set<LoginAttempt>().RemoveRange(oldLoginAttempts);

        await context.SaveChangesAsync();

        logger.LogInformation(
            "Cleaned up {EmailTokens} email tokens, {PasswordTokens} password tokens, {LoginAttempts} login attempts",
            expiredEmailTokens.Count, expiredPasswordTokens.Count, oldLoginAttempts.Count);
    }

    #endregion

    #region Helpers

    private static string GenerateSecureToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    private static bool IsPasswordStrong(string password)
    {
        if (password.Length < 8) return false;
        var checks = new Func<char, bool>[] { char.IsUpper, char.IsLower, char.IsDigit, ch => !char.IsLetterOrDigit(ch) };
        return checks.All(password.Any);
    }

    #endregion
}