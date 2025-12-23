using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Identity;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IIdentityService identityService) : ControllerBase
{
    private readonly IIdentityService _identityService = identityService;

    /// <summary>
    /// Authenticate user with email and password
    /// </summary>
    [HttpPost("login")]
    [ProducesResponseType(typeof(LoginResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { error = "Email and password are required" });
        }

        var response = await _identityService.AuthenticateAsync(request.Email, request.Password);

        if (response is { Success: false, RequiresMfa: false})
        {
            return BadRequest(response);
        }

        return Ok(response);
    }

    /// <summary>
    /// Check if email is available for registration
    /// </summary>
    [HttpGet("check-email")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public async Task<ActionResult> CheckEmailAvailability([FromQuery] string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return BadRequest(new { error = "Email is required" });
        }

        var isAvailable = await _identityService.IsEmailAvailableAsync(email);
        return Ok(new { email, available = isAvailable });
    }

    /// <summary>
    /// Check if username is available for registration
    /// </summary>
    [HttpGet("check-username")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
    public async Task<ActionResult> CheckUsernameAvailability([FromQuery] string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(new { error = "Username is required" });
        }

        var isAvailable = await _identityService.IsUsernameAvailableAsync(username);
        return Ok(new { username, available = isAvailable });
    }

    /// <summary>
    /// Get user profile by ID (TODO: Add authentication requirement)
    /// </summary>
    [HttpGet("profile/{userId}")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<UserDto>> GetProfile(Guid userId)
    {
        var user = await _identityService.GetUserByIdAsync(userId);

        if (user == null)
        {
            return NotFound(new { error = "User not found" });
        }

        return Ok(new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            Username = user.Username,
            FirstName = user.FirstName,
            LastName = user.LastName,
            ProfilePictureUrl = user.ProfilePictureUrl,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        });
    }

    /// <summary>
    /// Update user profile (TODO: Add authentication requirement)
    /// </summary>
    [HttpPut("profile/{userId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> UpdateProfile(
        Guid userId,
        [FromBody] UpdateProfileRequest request)
    {
        var success = await _identityService.UpdateUserAsync(
            userId,
            request.FirstName,
            request.LastName,
            request.ProfilePictureUrl);

        if (!success)
        {
            return NotFound(new { error = "User not found" });
        }

        return Ok(new { message = "Profile updated successfully" });
    }

    /// <summary>
    /// Change user password (TODO: Add authentication requirement)
    /// </summary>
    [HttpPost("change-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.CurrentPassword) || 
            string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new { error = "Both current and new password are required" });
        }

        if (request.NewPassword.Length < 8)
        {
            return BadRequest(new { error = "New password must be at least 8 characters" });
        }

        try
        {
            var success = await _identityService.ChangePasswordAsync(
                request.UserId,
                request.CurrentPassword,
                request.NewPassword);

            if (!success)
            {
                return BadRequest(new { error = "Current password is incorrect" });
            }

            return Ok(new { message = "Password changed successfully" });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}

// DTOs
public record UpdateProfileRequest
{
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? ProfilePictureUrl { get; init; }
}

public record ChangePasswordRequest
{
    public Guid UserId { get; init; }
    public string CurrentPassword { get; init; } = null!;
    public string NewPassword { get; init; } = null!;
}