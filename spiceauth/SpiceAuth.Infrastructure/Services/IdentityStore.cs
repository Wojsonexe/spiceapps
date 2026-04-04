using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Infrastructure.Services;

public class IdentityStore : IIdentityStore
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;

    public IdentityStore(ApplicationDbContext context, UserManager<ApplicationUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    public async Task<(List<ApplicationUser> Users, int Total)> GetUsersAsync(
        int page, int pageSize, string? search = null)
    {
        var query = _context.Set<ApplicationUser>().AsQueryable();
        
        if (!string.IsNullOrWhiteSpace(search))
        {
            var q = search.ToLower();
            query = query.Where(u =>
                u.Email!.ToLower().Contains(q) ||
                u.UserName!.ToLower().Contains(q) ||
                (u.FirstName != null && u.FirstName.ToLower().Contains(q)) ||
                (u.LastName != null && u.LastName.ToLower().Contains(q)));
        }

        var total = await query.CountAsync();
        var users = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return (users, total);
    }
    
    public async Task DeleteUserAsync(Guid userId)
    {
        var user = await _context.Set<ApplicationUser>()
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null) return;

        user.IsActive = false;
        user.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();
    }

    public async Task<ApplicationUser?> GetUserByEmailAsync(string email)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email == email);
    }

    public async Task<ApplicationUser?> GetUserByUsernameAsync(string username)
    {
        return await _context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.UserName == username);
    }
    
    public async Task<ApplicationUser?> GetUserAsync(Guid userId)
    {
        return await _context.Set<ApplicationUser>()
            .Include(u => u.MfaSettings)
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    public async Task SetUserSuspendedAsync(Guid userId, bool suspended)
    {
        var user = await _userManager.FindByIdAsync(userId.ToString())
                   ?? throw new InvalidOperationException($"User {userId} not found");

        user.IsSuspended = suspended;
        user.IsActive = !suspended;

        await _userManager.UpdateAsync(user);
    }
}