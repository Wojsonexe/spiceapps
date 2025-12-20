using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Application.Interfaces;

public interface IRegistrationService
{
    Task<RegistrationRequest> CreateRegistrationRequestAsync(
        string email, 
        string username, 
        string passwordHash, 
        string sourceApp,
        string? ipAddress = null,
        string? userAgent = null);
    
    Task<RegistrationRequest?> GetRequestByIdAsync(Guid requestId);
    Task<List<RegistrationRequest>> GetPendingRequestsAsync(int page = 1, int pageSize = 20);
    Task<User> ApproveRequestAsync(Guid requestId, Guid adminUserId);
    Task RejectRequestAsync(Guid requestId, Guid adminUserId, string reason);
    Task<bool> IsPendingRequestByEmailAsync(string email);
}