using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.Registration;
using SpiceAuth.Application.Services.Registration;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class RegistrationController(IRegistrationService registrationService) : ControllerBase
{
    private readonly IRegistrationService _registrationService = registrationService;

    /// <summary>
    /// Submit a new registration request
    /// </summary>
    [HttpPost("request")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<RegistrationRequestDto>> CreateRegistrationRequest(
        [FromBody] CreateRegistrationRequest request)
    {
        try
        {
            var registrationRequest = await _registrationService.CreateRegistrationRequestAsync(request);
            var dto = new RegistrationRequestDto
            {
                Id = registrationRequest.Id,
                Email = registrationRequest.Email,
                Username = registrationRequest.Username,
                FirstName = registrationRequest.FirstName,
                LastName = registrationRequest.LastName,
                Status = registrationRequest.Status.ToString(),
                RequestedAt = registrationRequest.RequestedAt
            };

            return CreatedAtAction(
                nameof(GetRegistrationRequest),
                new { id = dto.Id },
                dto);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Get a specific registration request
    /// </summary>
    [HttpGet("{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<RegistrationRequestDto>> GetRegistrationRequest(Guid id)
    {
        var request = await _registrationService.GetRegistrationRequestAsync(id);
        
        if (request == null)
            return NotFound();

        return Ok(request);
    }

    /// <summary>
    /// Get all pending registration requests (Admin only - TODO: Add authorization)
    /// </summary>
    [HttpGet("pending")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<List<RegistrationRequestDto>>> GetPendingRequests()
    {
        var requests = await _registrationService.GetPendingRequestsAsync();
        return Ok(requests);
    }

    /// <summary>
    /// Get all registration requests with pagination (Admin only - TODO: Add authorization)
    /// </summary>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<List<RegistrationRequestDto>>> GetAllRequests(
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50)
    {
        var requests = await _registrationService.GetAllRequestsAsync(skip, take);
        return Ok(requests);
    }

    /// <summary>
    /// Approve a registration request (Admin only - TODO: Add authorization)
    /// </summary>
    [HttpPost("{id}/approve")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> ApproveRegistration(
        Guid id,
        [FromBody] ApproveRegistrationRequest request)
    {
        // TODO: Get current admin user ID from JWT
        var adminUserId = Guid.NewGuid(); // TEMPORARY - will be replaced with actual auth

        try
        {
            var success = await _registrationService.ApproveRegistrationAsync(
                id,
                adminUserId,
                request.Notes);

            if (!success)
                return NotFound();

            return Ok(new { message = "Registration approved successfully" });
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Reject a registration request (Admin only - TODO: Add authorization)
    /// </summary>
    [HttpPost("{id}/reject")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> RejectRegistration(
        Guid id,
        [FromBody] RejectRegistrationRequest request)
    {
        // TODO: Get current admin user ID from JWT
        var adminUserId = Guid.NewGuid(); // TEMPORARY

        var success = await _registrationService.RejectRegistrationAsync(
            id,
            adminUserId,
            request.Reason);

        if (!success)
            return NotFound();

        return Ok(new { message = "Registration rejected" });
    }

    /// <summary>
    /// Get registration statistics (Admin only - TODO: Add authorization)
    /// </summary>
    [HttpGet("statistics")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<RegistrationStatistics>> GetStatistics()
    {
        var stats = await _registrationService.GetStatisticsAsync();
        return Ok(stats);
    }
}