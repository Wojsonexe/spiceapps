using SpiceAuth.Application.DTOs.Registration;
using SpiceAuth.Core.Entities.Registration;

namespace SpiceAuth.Application.Services.Registration;

public interface IRegistrationService
{
    // Registration requests
    Task<RegistrationRequest> CreateRegistrationRequestAsync(CreateRegistrationRequest request);
    Task<RegistrationRequestDto?> GetRegistrationRequestAsync(Guid requestId);
    Task<List<RegistrationRequestDto>> GetPendingRequestsAsync();
    Task<List<RegistrationRequestDto>> GetAllRequestsAsync(int skip = 0, int take = 50);
    
    // Approval workflow
    Task<bool> ApproveRegistrationAsync(Guid requestId, Guid approvedByUserId, string? notes = null);
    Task<bool> RejectRegistrationAsync(Guid requestId, Guid rejectedByUserId, string reason);
    
    // Statistics
    Task<RegistrationStatistics> GetStatisticsAsync();
}

public record RegistrationStatistics
{
    public int PendingCount { get; init; }
    public int ApprovedCount { get; init; }
    public int RejectedCount { get; init; }
    public int TotalCount { get; init; }
}