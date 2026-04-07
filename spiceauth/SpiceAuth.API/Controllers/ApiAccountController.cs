using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Identity;

namespace SpiceAuth.API.Controllers;

[Route("api/account")]
[ApiController]
public class ApiAccountController(
    IIdentityService identityService
    ) : ControllerBase
{
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var result = await identityService.CreateUserAsync(
            request.Email,
            request.Username,
            request.Password,
            request.FirstName ?? "",
            request.LastName ?? "");

        if (!result.Success)
            return BadRequest(new { error = result.Message });

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = Request.Headers.UserAgent.ToString();
        await identityService.GenerateEmailVerificationTokenAsync(result.UserId!.Value, ip, ua);

        return Ok(new { message = "Rejestracja udana. Sprawdź email.", userId = result.UserId });
    }
    
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = Request.Headers.UserAgent.ToString();

        var result = await identityService.AuthenticateAsync(request.Email, request.Password, ip, ua);

        if (!result.Success)
        {
            if (result.RequiresMfa)
                return Ok(new { requiresMfa = true, mfaToken = result.MfaToken });

            if (result.RequiresEmailVerification)
                return StatusCode(403, new { error = result.Message, requiresEmailVerification = true });

            return Unauthorized(new { error = result.Message });
        }
        
        return Ok(new {
            accessToken  = result.AccessToken,
            refreshToken = result.RefreshToken,
        });
    }

    // ── MFA CHALLENGE ───────────────────────────────────────────────────────────
    [HttpPost("mfa-challenge")]
    [AllowAnonymous]
    public async Task<IActionResult> MfaChallenge([FromBody] MfaChallengeRequest request)
    {
        var result = await identityService.ValidateMfaTokenAsync(request.MfaToken);

        if (!result.Success)
            return BadRequest(new { error = result.Message });

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ua = Request.Headers.UserAgent.ToString();

        var loginResult = await identityService.CompleteMfaLoginAsync(
            request.MfaToken, 
            request.Code, 
            ip, 
            ua);

        if (!loginResult.Success)
            return BadRequest(new { error = loginResult.Message });

        return Ok(new {
            accessToken  = loginResult.AccessToken,
            refreshToken = loginResult.RefreshToken,
        });
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
    {
        var result = await identityService.RefreshTokenAsync(request.RefreshToken);

        if (!result.Success)
            return Unauthorized(new { error = result.Message });

        return Ok(new {
            accessToken  = result.AccessToken,
            refreshToken = result.RefreshToken
        });
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userIdClaim = User.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(userIdClaim))
            return BadRequest(new { error = "Brak user ID w tokenie" });

        await identityService.RevokeRefreshTokenAsync(userIdClaim);
        return Ok(new { message = "Wylogowano pomyślnie" });
    }
    
    [HttpGet("check")]
    [Authorize]
    public IActionResult Check()
    {
        var userId = User.FindFirst("sub")?.Value ?? "";
        var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "";
        var roles = User.FindAll(ClaimTypes.Role).Select(r => r.Value).ToArray();
    
        return Ok(new {
            authenticated = true,
            userId,
            email,
            roles
        });
    }

    [HttpGet("profile")]
    [Authorize]
    public async Task<IActionResult> GetProfile()
    {
        var userId = User.FindFirst("sub")?.Value;
        var result = await identityService.GetUserProfileAsync(Guid.Parse(userId!));
    
        if (!result.Success)
            return NotFound();
        
        return Ok(new {
            id = result.Data!.Id,
            email = result.Data.Email,
            firstName = result.Data.FirstName,
            lastName = result.Data.LastName,
            department = result.Data.Department,
            isApproved = result.Data.IsApproved,
            birthDay = result.Data.BirthDay
        });
    }

    [HttpPost("update-profile")]
    [Authorize]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
    {
        var userId = User.FindFirst("sub")?.Value;
        var result = await identityService.UpdateUserProfileAsync(
            Guid.Parse(userId!), 
            request.FirstName, 
            request.LastName, 
            request.Department,
            request.BirthDay);
        
        return result.Success ? Ok(new { message = result.Message }) : BadRequest(new { error = result.Message });
    }
}
