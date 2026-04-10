using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Json.Serialization;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(
    IIdentityService identityService,
    IAuditService auditService,
    ITokenService tokenService,
    ILogger<AuthController> logger) : ControllerBase
{
    private readonly IIdentityService _identityService = identityService;
    private readonly IAuditService _auditService = auditService;
    private readonly ITokenService _tokenService = tokenService;
    private readonly ILogger<AuthController> _logger = logger;

    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    private string Ua() => HttpContext.Request.Headers.UserAgent.ToString();

    // ─── Login ────────────────────────────────────────────────────────────────

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthTokenResponse>> Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { error = "Email and password are required" });

        _logger.LogInformation("Login attempt for {Email} from {IP}", request.Login, Ip());

        var response = await _identityService.AuthenticateAsync(request.Login, request.Password, Ip(), Ua());

        if (response is { Success: false, RequiresMfa: false })
        {
            await _auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: request.Login,
                resourceType: "Auth",
                success: false,
                failureReason: "Invalid credentials",
                ipAddress: Ip(),
                userAgent: Ua());

            _logger.LogWarning("Failed login for {Email}", request.Login);

            // FIX: return 401, not 400, so frontend can distinguish auth errors
            return Unauthorized(new
            {
                success = false,
                message = response.Message ?? "Invalid credentials",
                requires_mfa = response.RequiresMfa,
                requires_email_verification = response.RequiresEmailVerification
            });
        }

        await _auditService.LogAsync(
            action: AuditAction.Login,
            actorEmail: request.Login,
            resourceType: "Auth",
            ipAddress: Ip(),
            userAgent: Ua());

        _logger.LogInformation("Successful login for {Email}", request.Login);

        // FIX: return snake_case keys that frontend already expects
        return Ok(new AuthTokenResponse
        {
            Success = true,
            AccessToken = response.AccessToken,
            RefreshToken = response.RefreshToken,
            ExpiresIn = response.ExpiresIn,
            TokenType = "Bearer"
        });
    }

    // ─── Refresh (with rotation + reuse detection) ────────────────────────────

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthTokenResponse>> Refresh([FromBody] RefreshTokenRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return BadRequest(new { error = "Refresh token is required" });

        try
        {
            // Delegate to IdentityService which calls TokenService.RotateRefreshTokenAsync internally
            var response = await _identityService.RefreshTokenAsync(request.RefreshToken);

            if (!response.Success)
                return Unauthorized(new { error = response.Message });

            return Ok(new AuthTokenResponse
            {
                Success = true,
                AccessToken = response.AccessToken,
                RefreshToken = response.RefreshToken,
                ExpiresIn = response.ExpiresIn,
                TokenType = "Bearer"
            });
        }
        catch (Microsoft.IdentityModel.Tokens.SecurityTokenException ex)
        {
            _logger.LogWarning(ex, "Refresh token security violation");
            // Reuse detected — all sessions were already revoked inside RotateRefreshTokenAsync
            return Unauthorized(new { error = "Session expired. Please log in again." });
        }
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

    // ─── Email verification ───────────────────────────────────────────────────

    [HttpPost("resend-verification")]
    [AllowAnonymous]
    public async Task<ActionResult> ResendEmailVerification([FromBody] ResendVerificationRequest request)
    {
        var success = await _identityService.ResendEmailVerificationAsync(request.UserId);
        if (!success)
            return BadRequest(new { error = "Unable to send verification email." });
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
            return BadRequest(new { error = "Invalid or expired verification token" });

        return Ok(new { message = "Email verified successfully" });
    }

    // ─── Password reset ───────────────────────────────────────────────────────

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email))
            return BadRequest(new { error = "Email is required" });

        await _identityService.GeneratePasswordResetTokenAsync(request.Email, Ip(), Ua());
        return Ok(new { message = "If an account exists, a reset link has been sent." });
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
            return BadRequest(new { error = "Invalid or expired reset token" });

        return Ok(new { message = "Password reset successfully" });
    }

    // ─── Authenticated endpoints ──────────────────────────────────────────────

    [HttpGet("profile")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult<UserDto>> GetProfile()
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var user = await _identityService.GetUserByIdAsync(userId.Value);
        if (user is null) return NotFound(new { error = "User not found" });

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
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var success = await _identityService.UpdateUserAsync(
            userId.Value, request.FirstName, request.LastName, request.ProfilePictureUrl);

        if (!success) return NotFound(new { error = "User not found" });
        return Ok(new { message = "Profile updated successfully" });
    }

    [HttpPost("change-password")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var actorEmail = User.FindFirstValue(ClaimTypes.Email) ?? "unknown";

        if (string.IsNullOrWhiteSpace(request.CurrentPassword) || string.IsNullOrWhiteSpace(request.NewPassword))
            return BadRequest(new { error = "Both current and new password are required" });

        if (request.NewPassword.Length < 8)
            return BadRequest(new { error = "New password must be at least 8 characters" });

        try
        {
            var success = await _identityService.ChangePasswordAsync(
                userId.Value, request.CurrentPassword, request.NewPassword);

            if (!success)
            {
                await _auditService.LogAsync(AuditAction.PasswordChanged, actorEmail,
                    actorId: userId, resourceType: "User", resourceId: userId.ToString(),
                    success: false, failureReason: "Wrong current password",
                    ipAddress: Ip(), userAgent: Ua());

                return BadRequest(new { error = "Current password is incorrect" });
            }

            await _auditService.LogAsync(AuditAction.PasswordChanged, actorEmail,
                actorId: userId, resourceType: "User", resourceId: userId.ToString(),
                ipAddress: Ip(), userAgent: Ua());

            return Ok(new { message = "Password changed successfully" });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpGet("me")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult> Me()
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var result = await _identityService.GetUserProfileAsync(userId.Value);
        if (!result.Success) return NotFound(new { error = result.Message });
        return Ok(result.Data);
    }

    [HttpPost("link-discord")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<ActionResult> LinkDiscord([FromBody] LinkDiscordRequest request)
    {
        var userId = GetCurrentUserId();
        if (userId is null) return Unauthorized();

        var result = await _identityService.LinkDiscordAsync(userId.Value, request.DiscordId, request.DiscordUsername);
        if (!result) return BadRequest(new { error = "Failed to link Discord account" });

        return Ok(new { message = "Discord account linked successfully" });
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    private Guid? GetCurrentUserId()
    {
        var claim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(claim, out var id) ? id : null;
    }
}

// ─── Response DTO (snake_case JSON) ──────────────────────────────────────────

public class AuthTokenResponse
{
    [JsonPropertyName("success")]
    public bool Success { get; set; }

    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";
}

// ─── Request records ──────────────────────────────────────────────────────────

public record LinkDiscordRequest(string DiscordId, string DiscordUsername);
public record ChangePasswordRequest(string CurrentPassword, string NewPassword);
public record ResendVerificationRequest(Guid UserId);
public record VerifyEmailRequest(string Token);
public record ForgotPasswordRequest(string Email);
public record ResetPasswordRequest(string Token, string NewPassword);