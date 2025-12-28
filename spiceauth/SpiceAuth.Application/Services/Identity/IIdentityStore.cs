using SpiceAuth.Core.Entities.Authorization;

namespace SpiceAuth.Application.Services.Identity;

public interface IIdentityStore
{
    Task<IdentityUser?> GetUserAsync(Guid userId);
}