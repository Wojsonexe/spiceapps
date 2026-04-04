using SpiceAuth.Application.Common;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Application.Services.Identity;

public interface IIdentityService
{
    Task<LoginResponse> AuthenticateAsync(string email, string password, string ipAddress, string userAgent);

    Task<RegisterResponse> CreateUserAsync(string email, string username, string password, string firstName, string lastName);
    Task<ApplicationUser?> GetUserByIdAsync(Guid userId);
    Task<ApplicationUser?> GetUserByEmailAsync(string email);
    Task<ApplicationUser?> GetUserByUsernameAsync(string username);
    Task<bool> UpdateUserAsync(Guid userId, string? firstName, string? lastName, string? profilePictureUrl);
    Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword);
    Task<bool> SuspendUserAsync(Guid userId, DateTime? suspendedUntil, string reason);
    Task<bool> ActivateUserAsync(Guid userId);
    Task<bool> IsEmailAvailableAsync(string email);
    Task<bool> IsUsernameAvailableAsync(string username);
    Task<bool> ValidatePasswordAsync(Guid userId, string password);

    Task GenerateEmailVerificationTokenAsync(Guid userId, string ipAddress, string userAgent);
    Task<bool> VerifyEmailAsync(string token);
    Task<bool> ResendEmailVerificationAsync(Guid userId);

    Task<string?> GeneratePasswordResetTokenAsync(string email, string ipAddress, string userAgent);
    Task<bool> ResetPasswordAsync(string token, string newPassword);
    Task<bool> ValidatePasswordResetTokenAsync(string token);

    Task RecordLoginAttemptAsync(string email, bool isSuccessful, string ipAddress, string? userAgent, string? failureReason = null);
    Task<bool> IsAccountLockedAsync(string email);
    Task<int> GetFailedLoginAttemptsAsync(string email, TimeSpan timeWindow);
    
    Task<bool> LinkDiscordAsync(Guid userId, string discordId, string discordUsername);
    Task<ApplicationUser?> GetUserByDiscordIdAsync(string discordId);
    
    Task<LoginResponse> ValidateMfaTokenAsync(string mfaToken);
    Task<LoginResponse> CompleteMfaLoginAsync(string mfaToken, string code, string ipAddress, string userAgent);
    
    Task<LoginResponse> RefreshTokenAsync(string refreshToken);
    Task RevokeRefreshTokenAsync(string userId);
    
    Task CleanupExpiredTokensAsync();
    
    Task<UserProfileResult> GetUserProfileAsync(Guid userId);
    Task<OperationResult> UpdateUserProfileAsync(Guid userId, string? firstName, string? lastName, int department, DateOnly? birthDay);
}
