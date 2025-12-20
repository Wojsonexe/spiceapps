using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Application.Interfaces;

public interface IUserService
{
    Task<User?> GetUserByIdAsync(Guid userId);
    Task<User?> GetUserByEmailAsync(string email);
    Task<User?> GetUserByUsernameAsync(string username);
    Task<User?> ValidateCredentialsAsync(string email, string password);
    Task<User> CreateUserAsync(string email, string username, string passwordHash);
    Task<bool> UpdateLastLoginAsync(Guid userId);
    Task<List<string>> GetUserRolesAsync(Guid userId);
    Task<List<string>> GetUserScopesAsync(Guid userId);
}