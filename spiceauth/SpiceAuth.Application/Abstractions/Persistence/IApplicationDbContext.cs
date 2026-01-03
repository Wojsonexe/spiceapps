using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Abstractions.Persistence;

public interface IApplicationDbContext
{
    DbSet<User> Users { get; }
    DbSet<MfaSettings> MfaSettings { get;  }
    
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}