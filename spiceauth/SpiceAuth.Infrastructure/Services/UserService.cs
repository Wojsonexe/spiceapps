using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Interfaces;
using SpiceAuth.Domain.Entities;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Infrastructure.Services;

public class UserService : IUserService
{
    private readonly SpiceAuthDbContext _context;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<UserService> _logger;

    public UserService(
        SpiceAuthDbContext context,
        IPasswordHasher passwordHasher,
        ILogger<UserService> logger)
    {
        _context = context;
        _passwordHasher = passwordHasher;
        _logger = logger;
    }

    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        return await _context.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
            .Include(u => u.UserScopes).ThenInclude(us => us.Scope)
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    public async Task<User?> GetUserByEmailAsync(string email)
    {
        var normalized = email.ToUpperInvariant();
        return await _context.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
            .Include(u => u.UserScopes).ThenInclude(us => us.Scope)
            .FirstOrDefaultAsync(u => u.NormalizedEmail == normalized);
    }

    public async Task<User?> GetUserByUsernameAsync(string username)
    {
        return await _context.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
            .Include(u => u.UserScopes).ThenInclude(us => us.Scope)
            .FirstOrDefaultAsync(u => u.Username == username);
    }

    public async Task<User?> ValidateCredentialsAsync(string email, string password)
    {
        var user = await GetUserByEmailAsync(email);
        if (user == null)
        {
            _logger.LogWarning("User not found: {Email}", email);
            return null;
        }

        if (!user.IsActive)
        {
            _logger.LogWarning("User is not active: {Email}", email);
            return null;
        }

        if (user.IsLocked && user.LockedUntil > DateTime.UtcNow)
        {
            _logger.LogWarning("User is locked: {Email}", email);
            return null;
        }

        if (!_passwordHasher.VerifyPassword(user.PasswordHash, password))
        {
            _logger.LogWarning("Invalid password for: {Email}", email);
            
            // Increment failed login attempts
            user.FailedLoginAttempts++;
            if (user.FailedLoginAttempts >= 5)
            {
                user.IsLocked = true;
                user.LockedUntil = DateTime.UtcNow.AddMinutes(15);
                _logger.LogWarning("User locked due to failed attempts: {Email}", email);
            }
            await _context.SaveChangesAsync();
            
            return null;
        }

        // Reset failed attempts on successful login
        if (user.FailedLoginAttempts > 0)
        {
            user.FailedLoginAttempts = 0;
            user.IsLocked = false;
            user.LockedUntil = null;
            await _context.SaveChangesAsync();
        }

        return user;
    }

    public async Task<User> CreateUserAsync(string email, string username, string passwordHash)
    {
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            Username = username,
            PasswordHash = passwordHash,
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        return user;
    }

    public async Task<bool> UpdateLastLoginAsync(Guid userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user == null)
            return false;

        user.LastLoginAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<List<string>> GetUserRolesAsync(Guid userId)
    {
        return await _context.UserRoles
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.Role.Name)
            .ToListAsync();
    }

    public async Task<List<string>> GetUserScopesAsync(Guid userId)
    {
        return await _context.UserScopes
            .Where(us => us.UserId == userId)
            .Select(us => us.Scope.Name)
            .ToListAsync();
    }
}