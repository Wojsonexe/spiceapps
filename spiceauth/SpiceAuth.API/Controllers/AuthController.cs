using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    IIdentityService identityService,
    IAuditService auditService,
    ILogger<AuthController> logger) : ControllerBase
{
    private readonly IIdentityService _identityService = identityService;
    private readonly IAuditService _auditService = auditService;
    private readonly ILogger<AuthController> _logger = logger;

    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    private string Ua() => HttpContext.Request.Headers.UserAgent.ToString();

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { error = "Email and password are required" });

        _logger.LogInformation("Login attempt for {Email} from {IP}", request.Email, Ip());

        var response = await _identityService.AuthenticateAsync(request.Email, request.Password, Ip(), Ua());

        if (response is { Success: false, RequiresMfa: false })
        {
            await _auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: request.Email,
                resourceType: "Auth",
                success: false,
                failureReason: "Invalid credentials",
                ipAddress: Ip(),
                userAgent: Ua());

            _logger.LogWarning("Failed login for {Email} from {IP}", request.Email, Ip());
            return BadRequest(response);
        }

        await _auditService.LogAsync(
            action: AuditAction.Login,
            actorEmail: request.Email,
            resourceType: "Auth",
            ipAddress: Ip(),
            userAgent: Ua());

        _logger.LogInformation("Successful login for {Email}", request.Email);
        return Ok(response);
    }

    [HttpGet("check-email")]
    [AllowAnonymous]
    public async Task<ActionResult> CheckEmailAvailability([FromQuery] string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return BadRequest(new { error = "Email is required" });

        var isAvailable = await _identityService.IsEmailAvailableAsync(email);
        return Ok(new { email, available = isAvailable });
    }

    [HttpGet("check-username")]
    [AllowAnonymous]
    public async Task<ActionResult> CheckUsernameAvailability([FromQuery] string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return BadRequest(new { error = "Username is required" });

        var isAvailable = await _identityService.IsUsernameAvailableAsync(username);
        return Ok(new { username, available = isAvailable });
    }

    [HttpPost("resend-verification")]
    [AllowAnonymous]
    public async Task<ActionResult> ResendEmailVerification([FromBody] ResendVerificationRequest request)
    {
        _logger.LogInformation("Resend verification for UserId={UserId}", request.UserId);
        var success = await _identityService.ResendEmailVerificationAsync(request.UserId);

        if (!success)
            return BadRequest(new { error = "Unable to send verification email. Email may already be verified." });

        return Ok(new { message = "Verification email sent" });
    }

    [HttpPost("verify-email")]
    [AllowAnonymous]
    public async Task<ActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
            return BadRequest(new { error = "Token is required" });

        var success = await _identityService.VerifyEmailAsync(request.Token);

        if (!success)
        {
            _logger.LogWarning("Invalid email verification token used");
            return BadRequest(new { error = "Invalid or expired verification token" });
        }

        _logger.LogInformation("Email verified successfully");
        return Ok(new { message = "Email verified successfully" });
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
            return BadRequest(new { error = "Email is required" });

        await _identityService.GeneratePasswordResetTokenAsync(request.Email, Ip(), Ua());

        return Ok(new { message = "If an account exists with this email, a password reset link has been sent." });
    }

    [HttpGet("validate-reset-token")]
    [AllowAnonymous]
    public async Task<ActionResult> ValidateResetToken([FromQuery] string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return BadRequest(new { error = "Token is required" });

        var isValid = await _identityService.ValidatePasswordResetTokenAsync(token);
        return Ok(new { valid = isValid });
    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<ActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
            return BadRequest(new { error = "Token and new password are required" });

        if (request.NewPassword.Length < 8)
            return BadRequest(new { error = "Password must be at least 8 characters" });

        var success = await _identityService.ResetPasswordAsync(request.Token, request.NewPassword);

        if (!success)
        {
            _logger.LogWarning("Invalid password reset token used");
            return BadRequest(new { error = "Invalid or expired reset token" });
        }

        _logger.LogInformation("Password reset successfully");
        return Ok(new { message = "Password reset successfully" });
    }

    [HttpGet("profile")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult<UserDto>> GetProfile()
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userIdClaim))
            return Unauthorized(new { error = "Invalid authentication token" });

        var userId = Guid.Parse(userIdClaim);
        var user = await _identityService.GetUserByIdAsync(userId);

        if (user == null)
            return NotFound(new { error = "User not found" });

        return Ok(new UserDto
        {
            Id = user.Id,
            Email = user.Email ?? string.Empty,
            Username = user.UserName ?? string.Empty,
            FirstName = user.FirstName,
            LastName = user.LastName,
            ProfilePictureUrl = user.ProfilePictureUrl,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt
        });
    }

    [HttpPut("profile")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userIdClaim))
            return Unauthorized(new { error = "Invalid authentication token" });

        var userId = Guid.Parse(userIdClaim);
        var success = await _identityService.UpdateUserAsync(
            userId, request.FirstName, request.LastName, request.ProfilePictureUrl);

        if (!success)
            return NotFound(new { error = "User not found" });

        return Ok(new { message = "Profile updated successfully" });
    }

    [HttpPost("change-password")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userIdClaim))
            return Unauthorized(new { error = "Invalid authentication token" });

        var userId = Guid.Parse(userIdClaim);
        var actorEmail = User.FindFirstValue(ClaimTypes.Email) ?? "unknown";

        if (string.IsNullOrWhiteSpace(request.CurrentPassword) ||
            string.IsNullOrWhiteSpace(request.NewPassword))
            return BadRequest(new { error = "Both current and new password are required" });

        if (request.NewPassword.Length < 8)
            return BadRequest(new { error = "New password must be at least 8 characters" });

        try
        {
            var success = await _identityService.ChangePasswordAsync(
                userId, request.CurrentPassword, request.NewPassword);

            if (!success)
            {
                await _auditService.LogAsync(
                    action: AuditAction.PasswordChanged,
                    actorEmail: actorEmail,
                    actorId: userId,
                    resourceType: "User",
                    resourceId: userId.ToString(),
                    success: false,
                    failureReason: "Wrong current password",
                    ipAddress: Ip(),
                    userAgent: Ua());

                return BadRequest(new { error = "Current password is incorrect" });
            }

            await _auditService.LogAsync(
                action: AuditAction.PasswordChanged,
                actorEmail: actorEmail,
                actorId: userId,
                resourceType: "User",
                resourceId: userId.ToString(),
                ipAddress: Ip(),
                userAgent: Ua());

            return Ok(new { message = "Password changed successfully" });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Password change failed for user {UserId}", userId);
            return BadRequest(new { error = ex.Message });
        }
    }
    
    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<ActionResult<LoginResponse>> Refresh([FromBody] RefreshTokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return BadRequest(new { error = "Refresh token is required" });

        var response = await _identityService.RefreshTokenAsync(request.RefreshToken);

        if (!response.Success)
            return Unauthorized(new { error = response.Message });

        return Ok(response);
    }
    
    [HttpGet("me")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult> Me()
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userIdClaim)) return Unauthorized();

        var userId = Guid.Parse(userIdClaim);
        var result = await _identityService.GetUserProfileAsync(userId);

        if (!result.Success) return NotFound(new { error = result.Message });

        return Ok(result.Data);
    }
    
    [HttpPost("link-discord")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult> LinkDiscord([FromBody] LinkDiscordRequest request)
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userIdClaim)) return Unauthorized();

        var userId = Guid.Parse(userIdClaim);
        var user = await _identityService.GetUserByIdAsync(userId);
        if (user == null) return NotFound();

        // Zapisz discordId na userze
        var result = await _identityService.LinkDiscordAsync(userId, request.DiscordId, request.DiscordUsername);
        if (!result) return BadRequest(new { error = "Failed to link Discord account" });

        return Ok(new { message = "Discord account linked successfully" });
    }
}

public record LinkDiscordRequest
{
    public string DiscordId { get; init; } = null!;
    public string DiscordUsername { get; init; } = null!;
}

public record ChangePasswordRequest
{
    public string CurrentPassword { get; init; } = null!;
    public string NewPassword { get; init; } = null!;
}

public record ResendVerificationRequest { public Guid UserId { get; init; } }
public record VerifyEmailRequest { public string Token { get; init; } = null!; }
public record ForgotPasswordRequest { public string Email { get; init; } = null!; }
public record ResetPasswordRequest
{
    public string Token { get; init; } = null!;
    public string NewPassword { get; init; } = null!;
}
