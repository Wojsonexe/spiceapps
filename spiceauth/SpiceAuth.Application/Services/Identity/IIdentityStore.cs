using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Application.Services.Identity;

public interface IIdentityStore
{
    Task<(List<ApplicationUser> Users, int Total)> GetUsersAsync(
        int page, int pageSize, string? search = null);
    Task<ApplicationUser?> GetUserByEmailAsync(string email);
    Task<ApplicationUser?> GetUserByUsernameAsync(string username);
    
    Task DeleteUserAsync(Guid userId);
    
    Task<ApplicationUser?> GetUserAsync(Guid userId);
    Task SetUserSuspendedAsync(Guid userId, bool suspended);
}