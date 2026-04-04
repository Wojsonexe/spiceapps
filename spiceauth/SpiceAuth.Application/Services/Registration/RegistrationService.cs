using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.DTOs.Registration;
using SpiceAuth.Application.Services.Email;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Core.Entities.Registration;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.Application.Services.Registration;

public sealed class RegistrationService : IRegistrationService
{
    private readonly DbContext _context;
    private readonly IIdentityService _identityService;
    private readonly IEmailService _emailService;
    private readonly ILogger<RegistrationService> _logger;

    public RegistrationService(
        DbContext context,
        IIdentityService identityService,
        IEmailService emailService,
        ILogger<RegistrationService> logger)
    {
        _context = context;
        _identityService = identityService;
        _emailService = emailService;
        _logger = logger;
    }
    
    public async Task<RegistrationRequest> CreateRegistrationRequestAsync(CreateRegistrationRequest request)
    {
        // Validate email is not already registered or pending
        var existingUser = await _identityService.GetUserByEmailAsync(request.Email);
        if (existingUser != null)
        {
            throw new InvalidOperationException("Email is already registered");
        }

        var existingRequest = await _context.Set<RegistrationRequest>()
            .FirstOrDefaultAsync(r => r.Email.ToLower() == request.Email.ToLower() 
                                   && r.Status == RegistrationStatus.Pending);
        
        if (existingRequest != null)
        {
            throw new InvalidOperationException("Registration request already pending for this email");
        }

        // Validate username availability
        if (!await _identityService.IsUsernameAvailableAsync(request.Username))
        {
            throw new InvalidOperationException("Username is already taken");
        }

        var registrationRequest = new RegistrationRequest
        {
            Id = Guid.NewGuid(),
            Email = request.Email.ToLower(),
            Username = request.Username,
            FirstName = request.FirstName,
            LastName = request.LastName,
            Status = RegistrationStatus.Pending,
            RequestedAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow
        };

        _context.Set<RegistrationRequest>().Add(registrationRequest);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Registration request created: {RequestId} for email {Email}", 
            registrationRequest.Id, 
            registrationRequest.Email);

        return registrationRequest;
    }

    public async Task<RegistrationRequestDto?> GetRegistrationRequestAsync(Guid requestId)
    {
        var request = await _context.Set<RegistrationRequest>()
            .FirstOrDefaultAsync(r => r.Id == requestId);

        return request != null ? MapToDto(request) : null;
    }

    public async Task<List<RegistrationRequestDto>> GetPendingRequestsAsync()
    {
        var requests = await _context.Set<RegistrationRequest>()
            .Where(r => r.Status == RegistrationStatus.Pending)
            .OrderBy(r => r.RequestedAt)
            .ToListAsync();

        return requests.Select(MapToDto).ToList();
    }

    public async Task<List<RegistrationRequestDto>> GetAllRequestsAsync(int skip = 0, int take = 50)
    {
        var requests = await _context.Set<RegistrationRequest>()
            .OrderByDescending(r => r.RequestedAt)
            .Skip(skip)
            .Take(take)
            .ToListAsync();

        return requests.Select(MapToDto).ToList();
    }

    public async Task<bool> ApproveRegistrationAsync(Guid requestId, Guid approvedByUserId, string? notes = null)
    {
        var request = await _context.Set<RegistrationRequest>()
            .FirstOrDefaultAsync(r => r.Id == requestId);

        if (request == null)
        {
            _logger.LogWarning("Registration request not found: {RequestId}", requestId);
            return false;
        }

        if (request.Status != RegistrationStatus.Pending)
        {
            _logger.LogWarning(
                "Cannot approve registration request {RequestId} - status is {Status}", 
                requestId, 
                request.Status);
            return false;
        }

        try
        {
            var registerResult = await _identityService.CreateUserAsync(
                email: request.Email,
                username: request.Username,
                password: "",
                firstName: request.FirstName ?? "",
                lastName: request.LastName ?? ""
            );
            
            if (!registerResult.Success)
            {
                _logger.LogError("Failed to create user for request {RequestId}: {Message}",
                    requestId, registerResult.Message);
                return false;
            }

            var userId = registerResult.UserId!.Value;

            await _identityService.ActivateUserAsync(userId);

            request.Status = RegistrationStatus.Approved;
            request.ProcessedAt = DateTime.UtcNow;
            request.ProcessedByUserId = approvedByUserId;
            request.Notes = notes;
            request.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            _logger.LogInformation(
                "Registration request approved: {RequestId} by user {ApprovedBy}. User created: {UserId}",
                requestId, approvedByUserId, userId);

            await _emailService.SendRegistrationApprovedAsync(request.Email, request.Username);
            await _identityService.GenerateEmailVerificationTokenAsync(userId, "system", "registration-approval");

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to approve registration request {RequestId}",
                requestId);
            throw;
        }
    }

    public async Task<bool> RejectRegistrationAsync(Guid requestId, Guid rejectedByUserId, string reason)
    {
        var request = await _context.Set<RegistrationRequest>()
            .FirstOrDefaultAsync(r => r.Id == requestId);

        if (request == null)
        {
            _logger.LogWarning("Registration request not found: {RequestId}", requestId);
            return false;
        }

        if (request.Status != RegistrationStatus.Pending)
        {
            _logger.LogWarning(
                "Cannot reject registration request {RequestId} - status is {Status}",
                requestId,
                request.Status);
            return false;
        }

        request.Status = RegistrationStatus.Rejected;
        request.ProcessedAt = DateTime.UtcNow;
        request.ProcessedByUserId = rejectedByUserId;
        request.RejectionReason = reason;
        request.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Registration request rejected: {RequestId} by user {RejectedBy}. Reason: {Reason}",
            requestId,
            rejectedByUserId,
            reason);

        await _emailService.SendRegistrationRejectedAsync(request.Email, request.Username, reason);

        return true;
    }

    public async Task<RegistrationStatistics> GetStatisticsAsync()
    {
        var all = await _context.Set<RegistrationRequest>().ToListAsync();

        return new RegistrationStatistics
        {
            PendingCount = all.Count(r => r.Status == RegistrationStatus.Pending),
            ApprovedCount = all.Count(r => r.Status == RegistrationStatus.Approved),
            RejectedCount = all.Count(r => r.Status == RegistrationStatus.Rejected),
            TotalCount = all.Count
        };
    }

    private static RegistrationRequestDto MapToDto(RegistrationRequest request)
    {
        return new RegistrationRequestDto
        {
            Id = request.Id,
            Email = request.Email,
            Username = request.Username,
            FirstName = request.FirstName,
            LastName = request.LastName,
            Status = request.Status.ToString(),
            RequestedAt = request.RequestedAt,
            ProcessedAt = request.ProcessedAt,
            RejectionReason = request.RejectionReason
        };
    }
}
