using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Core.Entities.Authorization;

namespace SpiceAuth.Infrastructure.Identity;

public sealed class EfIdentityStore(DbContext context) : IIdentityStore
{
    public Task<IdentityUser?> GetUserAsync(Guid id)
        => context.Set<IdentityUser>()
            .Include(u => u.Roles)
            .ThenInclude(r => r.Role)
            .FirstOrDefaultAsync(u => u.Id == id);
}
