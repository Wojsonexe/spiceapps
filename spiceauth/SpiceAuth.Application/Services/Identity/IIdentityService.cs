using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Application.Services.Identity;

public interface IIdentityService
{
    // Authentication
    Task<LoginResponse> AuthenticateAsync(
        string email,
        string password,
        string? ipAddress = null,
        string? userAgent = null);
    Task<User?> GetUserByIdAsync(Guid userId);
    Task<User?> GetUserByEmailAsync(string email);
    Task<User?> GetUserByUsernameAsync(string username);
    
    // User Management
    Task<User> CreateUserAsync(string email, string username, string? password, string? firstName, string? lastName);
    Task<bool> UpdateUserAsync(Guid userId, string? firstName, string? lastName, string? profilePictureUrl);
    Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword);
    Task<bool> SuspendUserAsync(Guid userId, DateTime? suspendedUntil, string reason);
    Task<bool> ActivateUserAsync(Guid userId);
    
    // Validation
    Task<bool> IsEmailAvailableAsync(string email);
    Task<bool> IsUsernameAvailableAsync(string username);
    Task<bool> ValidatePasswordAsync(Guid userId, string password);
    
    Task<string> GenerateEmailVerificationTokenAsync(Guid userId, string ipAddress, string userAgent);
    Task<bool> VerifyEmailAsync(string token);
    Task<bool> ResendEmailVerificationAsync(Guid userId);
    
    // Password Reset
    Task<string?> GeneratePasswordResetTokenAsync(string email, string ipAddress, string userAgent);
    Task<bool> ResetPasswordAsync(string token, string newPassword);
    Task<bool> ValidatePasswordResetTokenAsync(string token);
    
    // Account Lockout
    Task RecordLoginAttemptAsync(string email, bool isSuccessful, string ipAddress, string? userAgent, string? failureReason = null);
    Task<bool> IsAccountLockedAsync(string email);
    Task<int> GetFailedLoginAttemptsAsync(string email, TimeSpan timeWindow);
}