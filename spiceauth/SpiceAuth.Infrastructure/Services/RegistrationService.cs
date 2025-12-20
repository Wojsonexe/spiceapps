using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Interfaces;
using SpiceAuth.Domain.Entities;
using SpiceAuth.Domain.Enums;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Infrastructure.Services;

public class RegistrationService : IRegistrationService
{
    private readonly SpiceAuthDbContext _context;
    private readonly ILogger<RegistrationService> _logger;

    public RegistrationService(
        SpiceAuthDbContext context,
        ILogger<RegistrationService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<RegistrationRequest> CreateRegistrationRequestAsync(
        string email, 
        string username, 
        string passwordHash, 
        string sourceApp,
        string? ipAddress = null,
        string? userAgent = null)
    {
        var request = new RegistrationRequest
        {
            Id = Guid.NewGuid(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            Username = username,
            PasswordHash = passwordHash,
            SourceApp = sourceApp,
            Status = RegistrationRequestStatus.Pending,
            SubmittedAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow,
            IpAddress = ipAddress,
            UserAgent = userAgent
        };

        await _context.RegistrationRequests.AddAsync(request);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Registration request created: {Email} from {SourceApp}", email, sourceApp);

        return request;
    }

    public async Task<RegistrationRequest?> GetRequestByIdAsync(Guid requestId)
    {
        return await _context.RegistrationRequests
            .Include(r => r.ReviewedBy)
            .FirstOrDefaultAsync(r => r.Id == requestId);
    }

    public async Task<List<RegistrationRequest>> GetPendingRequestsAsync(int page = 1, int pageSize = 20)
    {
        return await _context.RegistrationRequests
            .Where(r => r.Status == RegistrationRequestStatus.Pending)
            .OrderBy(r => r.SubmittedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
    }

        public async Task<User> ApproveRequestAsync(Guid requestId, Guid adminUserId)
    {
        var strategy = _context.Database.CreateExecutionStrategy();

        return await strategy.ExecuteAsync(async () =>
        {
            await using var transaction =
                await _context.Database.BeginTransactionAsync();

            try
            {
                // 1. Admin MUSI istnieć (w tej samej strategii)
                var admin = await _context.Users
                    .AsNoTracking()
                    .FirstOrDefaultAsync(u => u.Id == adminUserId);

                if (admin == null)
                    throw new InvalidOperationException("Admin user not found");

                // 2. Request – tracking REQUIRED
                var request = await _context.RegistrationRequests
                    .FirstOrDefaultAsync(r => r.Id == requestId);

                if (request == null)
                    throw new InvalidOperationException("Registration request not found");

                if (request.Status != RegistrationRequestStatus.Pending)
                    throw new InvalidOperationException("Request already processed");

                // 3. Create user
                var user = new User
                {
                    Id = Guid.NewGuid(),
                    Email = request.Email,
                    NormalizedEmail = request.NormalizedEmail,
                    Username = request.Username,
                    PasswordHash = request.PasswordHash,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                _context.Users.Add(user);

                // 4. Role
                var userRole = await _context.Roles
                    .AsNoTracking()
                    .FirstAsync(r => r.Name == "User");

                _context.UserRoles.Add(new UserRole
                {
                    UserId = user.Id,
                    RoleId = userRole.Id,
                    GrantedAt = DateTime.UtcNow
                });

                // 5. Scopes
                var defaultScopes = await _context.Scopes
                    .AsNoTracking()
                    .Where(s => new[]
                    {
                        "openid", "profile", "user:read", "user:write"
                    }.Contains(s.Name))
                    .ToListAsync();

                foreach (var scope in defaultScopes)
                {
                    _context.UserScopes.Add(new UserScope
                    {
                        UserId = user.Id,
                        ScopeId = scope.Id,
                        GrantedByUserId = adminUserId,
                        GrantedAt = DateTime.UtcNow
                    });
                }

                // 6. Update request
                request.Status = RegistrationRequestStatus.Approved;
                request.ReviewedAt = DateTime.UtcNow;
                request.ReviewedByUserId = adminUserId;

                // 7. Jeden commit
                await _context.SaveChangesAsync();
                await transaction.CommitAsync();

                _logger.LogInformation(
                    "Registration approved: {Email} by admin {AdminId}",
                    request.Email,
                    adminUserId);

                return user;
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        });
    }



    public async Task RejectRequestAsync(Guid requestId, Guid adminUserId, string reason)
    {
        var request = await GetRequestByIdAsync(requestId);
        if (request == null)
            throw new InvalidOperationException("Registration request not found");

        if (request.Status != RegistrationRequestStatus.Pending)
            throw new InvalidOperationException("Request already processed");

        request.Status = RegistrationRequestStatus.Rejected;
        request.ReviewedAt = DateTime.UtcNow;
        request.ReviewedByUserId = adminUserId;
        request.RejectionReason = reason;

        await _context.SaveChangesAsync();

        _logger.LogInformation("Registration rejected: {Email} by admin {AdminId}", request.Email, adminUserId);
    }

    public async Task<bool> IsPendingRequestByEmailAsync(string email)
    {
        var normalized = email.ToUpperInvariant();
        return await _context.RegistrationRequests
            .AnyAsync(r => r.NormalizedEmail == normalized && r.Status == RegistrationRequestStatus.Pending);
    }
}