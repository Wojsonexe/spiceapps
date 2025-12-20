using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.Responses;
using SpiceAuth.Application.Interfaces;

namespace SpiceAuth.Api.Controllers;

/// <summary>
/// Admin-only endpoints for managing users and registration requests.
/// TODO: Add [Authorize(Policy = "AdminApprove")] after OAuth is complete.
/// </summary>
[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    private readonly IRegistrationService _registrationService;
    private readonly IUserService _userService;
    private readonly ILogger<AdminController> _logger;

    public AdminController(
        IRegistrationService registrationService,
        IUserService userService,
        ILogger<AdminController> logger)
    {
        _registrationService = registrationService;
        _userService = userService;
        _logger = logger;
    }

    /// <summary>
    /// Get all pending registration requests.
    /// </summary>
    [HttpGet("registration-requests")]
    public async Task<IActionResult> GetPendingRequests([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var requests = await _registrationService.GetPendingRequestsAsync(page, pageSize);

        var dtos = requests.Select(r => new RegistrationRequestDto
        {
            Id = r.Id,
            Email = r.Email,
            Username = r.Username,
            SourceApp = r.SourceApp,
            Status = r.Status.ToString(),
            SubmittedAt = r.SubmittedAt,
            ReviewedAt = r.ReviewedAt,
            ReviewedByUsername = r.ReviewedBy?.Username,
            RejectionReason = r.RejectionReason
        }).ToList();

        return Ok(dtos);
    }

    /// <summary>
    /// Get specific registration request by ID.
    /// </summary>
    [HttpGet("registration-requests/{id}")]
    public async Task<IActionResult> GetRequest(Guid id)
    {
        var request = await _registrationService.GetRequestByIdAsync(id);
        if (request == null)
            return NotFound(new { error = "request_not_found", message = "Registration request not found" });

        var dto = new RegistrationRequestDto
        {
            Id = request.Id,
            Email = request.Email,
            Username = request.Username,
            SourceApp = request.SourceApp,
            Status = request.Status.ToString(),
            SubmittedAt = request.SubmittedAt,
            ReviewedAt = request.ReviewedAt,
            ReviewedByUsername = request.ReviewedBy?.Username,
            RejectionReason = request.RejectionReason
        };

        return Ok(dto);
    }

    /// <summary>
    /// Approve a registration request.
    /// Creates the user account and assigns default permissions.
    /// </summary>
    [HttpPost("registration-requests/{id}/approve")]
    public async Task<IActionResult> ApproveRequest(Guid id)
    {
        try
        {
            // TODO: Get admin user ID from JWT claims after OAuth is complete
            // For now, use the SuperAdmin ID from seed data
            var adminUserId = Guid.Parse("00000000-0000-0000-0000-000000000001");

            var user = await _registrationService.ApproveRequestAsync(id, adminUserId);

            _logger.LogInformation("Registration approved: {Email}", user.Email);

            return Ok(new
            {
                message = "Registration approved",
                userId = user.Id,
                username = user.Username,
                email = user.Email
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = "invalid_operation", message = ex.Message });
        }
    }

    /// <summary>
    /// Reject a registration request.
    /// </summary>
    [HttpPost("registration-requests/{id}/reject")]
    public async Task<IActionResult> RejectRequest(Guid id, [FromBody] RejectRequestDto dto)
    {
        try
        {
            // TODO: Get admin user ID from JWT claims after OAuth is complete
            var adminUserId = Guid.Parse("00000000-0000-0000-0000-000000000001");

            await _registrationService.RejectRequestAsync(id, adminUserId, dto.Reason);

            _logger.LogInformation("Registration rejected: {RequestId}", id);

            return Ok(new { message = "Registration rejected" });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = "invalid_operation", message = ex.Message });
        }
    }
}

public class RejectRequestDto
{
    public string Reason { get; set; } = "Not specified";
}