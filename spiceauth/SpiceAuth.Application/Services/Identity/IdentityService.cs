using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Application.Services.Identity;

public sealed class IdentityService(DbContext context, IPasswordHasher passwordHasher, ILogger<IdentityService> logger) : IIdentityService
{
    private readonly DbContext _context = context;
    private readonly IPasswordHasher _passwordHasher = passwordHasher;
    private readonly ILogger<IdentityService> _logger = logger;
    
    public async Task<LoginResponse> AuthenticateAsync(string email, string password)
    {
        var user = await GetUserByEmailAsync(email);

        if (user == null)
        {
            _logger.LogWarning("Login attempt for non-existent user: {Email}", email);
            return new LoginResponse
            {
                Success = false,
                Message = "Invalid email or password"
            };
        }

        if (!user.IsActive)
        {
            _logger.LogWarning("Login attempt for inactive user: {UserId}", user.Id);
            return new LoginResponse
            {
                Success = false,
                Message = "Account is not active. Please wait for approval."
            };
        }

        if (user.IsSuspended)
        {
            if (user.SuspendedUntil.HasValue && user.SuspendedUntil.Value > DateTime.UtcNow)
            {
                _logger.LogWarning("Login attempt for suspended user: {UserId}", user.Id);
                return new LoginResponse
                {
                    Success = false,
                    Message = $"Account is suspended until {user.SuspendedUntil.Value:yyyy-MM-dd HH:mm}"
                };
            }

            user.IsSuspended = false;
            user.SuspendedUntil = null;
            await _context.SaveChangesAsync();
        }

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            _logger.LogWarning("Login attempt with password for user without password: {UserId}", user.Id);
            return new LoginResponse
            {
                Success = false,
                Message = "Please login using your connected account (Discord, Google, etc.)"
            };
        }

        if (!_passwordHasher.VerifyPassword(password, user.PasswordHash))
        {
            _logger.LogWarning("Failed login attempt for user: {UserId}", user.Id);
            return new LoginResponse
            {
                Success = false,
                Message = "Invalid email or password"
            };
        }

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

        user.LastLoginAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();

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
}