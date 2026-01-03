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

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

        var response = await _identityService.AuthenticateAsync(request.Email, request.Password, ipAddress, userAgent);

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
    /// Request email verification (resend)
    /// </summary>
    [HttpPost("resend-verification")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> ResendEmailVerification([FromBody] ResendVerificationRequest request)
    {
        var success = await _identityService.ResendEmailVerificationAsync(request.UserId);
        
        if (!success)
        {
            return BadRequest(new { error = "Unable to send verification email. Email may already be verified." });
        }
        
        return Ok(new { message = "Verification email sent" });
    }

    /// <summary>
    /// Verify email with token
    /// </summary>
    [HttpPost("verify-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return BadRequest(new { error = "Token is required" });
        }
        
        var success = await _identityService.VerifyEmailAsync(request.Token);
        
        if (!success)
        {
            return BadRequest(new { error = "Invalid or expired verification token" });
        }
        
        return Ok(new { message = "Email verified successfully" });
    }

    /// <summary>
    /// Request password reset
    /// </summary>
    [HttpPost("forgot-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return BadRequest(new { error = "Email is required" });
        }
        
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();
        
        // Always return success to prevent email enumeration
        await _identityService.GeneratePasswordResetTokenAsync(request.Email, ipAddress, userAgent);
        
        return Ok(new { message = "If an account exists with this email, a password reset link has been sent." });
    }

    /// <summary>
    /// Validate password reset token
    /// </summary>
    [HttpGet("validate-reset-token")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult> ValidateResetToken([FromQuery] string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return BadRequest(new { error = "Token is required" });
        }
        
        var isValid = await _identityService.ValidatePasswordResetTokenAsync(token);
        
        return Ok(new { valid = isValid });
    }

    /// <summary>
    /// Reset password with token
    /// </summary>
    [HttpPost("reset-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new { error = "Token and new password are required" });
        }
        
        if (request.NewPassword.Length < 8)
        {
            return BadRequest(new { error = "Password must be at least 8 characters" });
        }
        
        var success = await _identityService.ResetPasswordAsync(request.Token, request.NewPassword);
        
        if (!success)
        {
            return BadRequest(new { error = "Invalid or expired reset token" });
        }
        
        return Ok(new { message = "Password reset successfully" });
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

public record ResendVerificationRequest
{
    public Guid UserId { get; init; }
}

public record VerifyEmailRequest
{
    public string Token { get; init; } = null!;
}

public record ForgotPasswordRequest
{
    public string Email { get; init; } = null!;
}

public record ResetPasswordRequest
{
    public string Token { get; init; } = null!;
    public string NewPassword { get; init; } = null!;
}