using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using SpiceAuth.Application.DTOs.Registration;
using SpiceAuth.Application.Services.Registration;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/registration")]
public class RegistrationController(
    IRegistrationService registrationService,
    IAuditService auditService,
    ILogger<RegistrationController> logger) : ControllerBase
{
    private readonly IRegistrationService _registrationService = registrationService;
    private readonly IAuditService _auditService = auditService;
    private readonly ILogger<RegistrationController> _logger = logger;

    private (Guid? id, string email) GetActor() => (
        Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null,
        User.FindFirstValue(ClaimTypes.Email) ?? "unknown"
    );

    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    [HttpPost("request")]
    [AllowAnonymous]
    public async Task<ActionResult<RegistrationRequestDto>> CreateRegistrationRequest(
        [FromBody] CreateRegistrationRequest request)
    {
        try
        {
            _logger.LogInformation(
                "Registration request: Email={Email}, Username={Username}, IP={IP}",
                request.Email, request.Username, Ip());

            var reg = await _registrationService.CreateRegistrationRequestAsync(request);

            await _auditService.LogAsync(
                action: AuditAction.RegistrationCreated,
                actorEmail: request.Email,
                resourceType: "Registration",
                resourceId: reg.Id.ToString(),
                resourceName: reg.Username,
                ipAddress: Ip());

            var dto = new RegistrationRequestDto
            {
                Id = reg.Id,
                Email = reg.Email,
                Username = reg.Username,
                FirstName = reg.FirstName,
                LastName = reg.LastName,
                Status = reg.Status.ToString(),
                RequestedAt = reg.RequestedAt
            };

            return CreatedAtAction(nameof(GetRegistrationRequest), new { id = dto.Id }, dto);
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Registration validation failed: {Message}", ex.Message);
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating registration request");
            return StatusCode(500, new { error = "An error occurred processing your registration" });
        }
    }

    [HttpGet("{id}")]
    [AllowAnonymous]
    public async Task<ActionResult<RegistrationRequestDto>> GetRegistrationRequest(Guid id)
    {
        var request = await _registrationService.GetRegistrationRequestAsync(id);

        if (request == null)
            return NotFound(new { error = "Registration request not found" });

        return Ok(request);
    }

    [HttpGet("pending")]
    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
    public async Task<ActionResult<List<RegistrationRequestDto>>> GetPendingRequests()
    {
        var requests = await _registrationService.GetPendingRequestsAsync();
        return Ok(requests);
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
    public async Task<ActionResult<List<RegistrationRequestDto>>> GetAllRequests(
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50)
    {
        if (take > 100)
            return BadRequest(new { error = "Maximum page size is 100" });

        var requests = await _registrationService.GetAllRequestsAsync(skip, take);
        return Ok(requests);
    }

    [HttpPost("{id}/approve")]
    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
    public async Task<ActionResult> ApproveRegistration(
        Guid id,
        [FromBody] ApproveRegistrationRequest request)
    {
        var adminUserIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(adminUserIdClaim))
            return Unauthorized(new { error = "Invalid authentication token" });

        var adminUserId = Guid.Parse(adminUserIdClaim);
        var (_, actorEmail) = GetActor();

        try
        {
            var reg = await _registrationService.GetRegistrationRequestAsync(id);
            var success = await _registrationService.ApproveRegistrationAsync(id, adminUserId, request.Notes);

            if (!success)
                return NotFound(new { error = "Registration request not found or already processed" });

            await _auditService.LogAsync(
                action: AuditAction.RegistrationApproved,
                actorEmail: actorEmail,
                actorId: adminUserId,
                resourceType: "Registration",
                resourceId: id.ToString(),
                resourceName: reg?.Username,
                ipAddress: Ip());

            return Ok(new { message = "Registration approved successfully", requestId = id });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error approving registration: RequestId={RequestId}", id);
            return StatusCode(500, new { error = "An error occurred processing the approval" });
        }
    }

    [HttpPost("{id}/reject")]
    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
    public async Task<ActionResult> RejectRegistration(
        Guid id,
        [FromBody] RejectRegistrationRequest request)
    {
        var adminUserIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(adminUserIdClaim))
            return Unauthorized(new { error = "Invalid authentication token" });

        var adminUserId = Guid.Parse(adminUserIdClaim);
        var (_, actorEmail) = GetActor();

        if (string.IsNullOrWhiteSpace(request.Reason))
            return BadRequest(new { error = "Rejection reason is required" });

        try
        {
            var reg = await _registrationService.GetRegistrationRequestAsync(id);
            var success = await _registrationService.RejectRegistrationAsync(id, adminUserId, request.Reason);

            if (!success)
                return NotFound(new { error = "Registration request not found or already processed" });

            await _auditService.LogAsync(
                action: AuditAction.RegistrationRejected,
                actorEmail: actorEmail,
                actorId: adminUserId,
                resourceType: "Registration",
                resourceId: id.ToString(),
                resourceName: reg?.Username,
                metadata: request.Reason,
                ipAddress: Ip());

            return Ok(new { message = "Registration rejected", requestId = id });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error rejecting registration: RequestId={RequestId}", id);
            return StatusCode(500, new { error = "An error occurred processing the rejection" });
        }
    }

    [HttpGet("statistics")]
    [Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
    public async Task<ActionResult<RegistrationStatistics>> GetStatistics()
    {
        var stats = await _registrationService.GetStatisticsAsync();
        return Ok(stats);
    }
}
