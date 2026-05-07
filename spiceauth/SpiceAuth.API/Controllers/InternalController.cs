using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using System.Security.Cryptography;
using System.Text;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/internal")]
[AllowAnonymous]
public sealed class InternalController(
    IOAuthService oauthService,
    ITokenService tokenService,
    DbContext context,
    UserManager<ApplicationUser> userManager,
    IConfiguration configuration,
    ILogger<InternalController> logger) : ControllerBase
{
    private readonly IOAuthService _oauthService = oauthService;
    private readonly ITokenService _tokenService = tokenService;
    private readonly DbContext _context = context;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    private readonly IConfiguration _configuration = configuration;
    private readonly ILogger<InternalController> _logger = logger;

    // ── Request models ────────────────────────────────────────────────────────

    public record IssueTokenRequest(
        Guid   UserId,
        string ClientId,
        string Scope,
        string Email,
        string FirstName,
        string LastName,
        bool   IsApproved);

    public record InternalRefreshTokenRequest(string RefreshToken);

    public record RevokeTokenRequest(string RefreshToken);

    public record RevokeAllTokensRequest(Guid UserId);

    // ── Secret validation ─────────────────────────────────────────────────────

    private bool IsSecretValid(out IActionResult? error)
    {
        var expected = _configuration["Internal:Secret"];
        if (string.IsNullOrWhiteSpace(expected))
        {
            _logger.LogError("Internal:Secret is not configured");
            error = StatusCode(503, new { error = "internal_misconfiguration" });
            return false;
        }

        var provided      = Request.Headers["X-Internal-Secret"].FirstOrDefault() ?? string.Empty;
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var providedBytes = Encoding.UTF8.GetBytes(provided);

        if (!CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes))
        {
            _logger.LogWarning("Invalid X-Internal-Secret from {IP}", HttpContext.Connection.RemoteIpAddress);
            error = Unauthorized(new { error = "invalid_secret" });
            return false;
        }

        error = null;
        return true;
    }

    private static string HashToken(string rawToken)
    {
        using var sha256 = SHA256.Create();
        return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(rawToken)));
    }

    // ── POST /api/internal/issue-token ───────────────────────────────────────

    [HttpPost("issue-token")]
    public async Task<IActionResult> IssueToken([FromBody] IssueTokenRequest request)
    {
        if (!IsSecretValid(out var secretError)) return secretError!;

        if (request.UserId == Guid.Empty)
            return BadRequest(new { error = "invalid_request", error_description = "userId is required" });

        if (string.IsNullOrWhiteSpace(request.ClientId))
            return BadRequest(new { error = "invalid_request", error_description = "clientId is required" });

        if (string.IsNullOrWhiteSpace(request.Email))
            return BadRequest(new { error = "invalid_request", error_description = "email is required" });

        // ── Auto-upsert ApplicationUser ───────────────────────────────────────
        var existing = await _userManager.FindByIdAsync(request.UserId.ToString());
        if (existing is null)
        {
            var newUser = new ApplicationUser
            {
                Id                 = request.UserId,
                Email              = request.Email.ToLower(),
                NormalizedEmail    = request.Email.ToUpper(),
                UserName           = request.Email.ToLower(),
                NormalizedUserName = request.Email.ToUpper(),
                FirstName          = request.FirstName,
                LastName           = request.LastName,
                IsApproved         = request.IsApproved,
                IsActive           = request.IsApproved,
                EmailConfirmed     = true,
                SecurityStamp      = Guid.NewGuid().ToString(),
                ConcurrencyStamp   = Guid.NewGuid().ToString(),
                CreatedAt          = DateTime.UtcNow,
            };

            var result = await _userManager.CreateAsync(newUser);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogError("Auto-upsert failed for userId={UserId}: {Errors}", request.UserId, errors);
                return StatusCode(500, new { error = "user_creation_failed", error_description = errors });
            }

            _logger.LogInformation("Auto-created ApplicationUser userId={UserId} email={Email}",
                request.UserId, request.Email);
        }

        // ── Issue tokens ──────────────────────────────────────────────────────
        try
        {
            var tokens = await _oauthService.CreateAccessAndRefreshTokensAsync(
                request.UserId,
                request.ClientId,
                request.Scope ?? "openid profile");

            return Ok(new
            {
                access_token  = tokens.AccessToken,
                refresh_token = tokens.RefreshToken,
                expires_in    = tokens.ExpiresIn
            });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "IssueToken failed for userId={UserId}, clientId={ClientId}",
                request.UserId, request.ClientId);
            return BadRequest(new { error = "invalid_request", error_description = ex.Message });
        }
    }

    // ── POST /api/internal/refresh-token ─────────────────────────────────────
    // Issues a new access token from a valid refresh token WITHOUT rotating it.
    // Used by spiceapi's generateAccess — spicehub reads the response as plain text.

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] InternalRefreshTokenRequest request)
    {
        if (!IsSecretValid(out var secretError)) return secretError!;

        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return BadRequest(new { error = "invalid_request", error_description = "refreshToken is required" });

        var hash = HashToken(request.RefreshToken);

        var rt = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(t => t.TokenHash == hash);

        if (rt is null || rt.IsRevoked || rt.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("refresh-token: invalid or expired token hash={Hash}", hash[..8]);
            return Unauthorized(new { error = "invalid_token" });
        }

        var tokenRequest = new TokenRequest
        {
            UserId   = rt.UserId,
            ClientId = rt.ClientId,
            Scope    = rt.Scope,
        };

        var accessToken = await _tokenService.GenerateAccessTokenAsync(tokenRequest);

        _logger.LogInformation("Issued access token via refresh for userId={UserId}", rt.UserId);

        // Return plain text — spicehub middleware reads this with res.text() and sets cookie
        return Content(accessToken, "text/plain");
    }

    // ── POST /api/internal/revoke-token ──────────────────────────────────────

    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
    {
        if (!IsSecretValid(out var secretError)) return secretError!;

        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return BadRequest(new { error = "invalid_request", error_description = "refreshToken is required" });

        var hash = HashToken(request.RefreshToken);

        var rt = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(t => t.TokenHash == hash);

        if (rt is null)
        {
            _logger.LogWarning("revoke-token: token not found hash={Hash}", hash[..8]);
            return NotFound(new { error = "token_not_found" });
        }

        rt.IsRevoked = true;
        await _context.SaveChangesAsync();

        _logger.LogInformation("Revoked refresh token for userId={UserId}", rt.UserId);
        return NoContent();
    }

    // ── POST /api/internal/revoke-all-tokens ─────────────────────────────────

    [HttpPost("revoke-all-tokens")]
    public async Task<IActionResult> RevokeAllTokens([FromBody] RevokeAllTokensRequest request)
    {
        if (!IsSecretValid(out var secretError)) return secretError!;

        if (request.UserId == Guid.Empty)
            return BadRequest(new { error = "invalid_request", error_description = "userId is required" });

        var tokens = await _context.Set<RefreshToken>()
            .Where(t => t.UserId == request.UserId && !t.IsRevoked)
            .ToListAsync();

        foreach (var token in tokens)
            token.IsRevoked = true;

        await _context.SaveChangesAsync();

        _logger.LogInformation("Revoked {Count} refresh tokens for userId={UserId}", tokens.Count, request.UserId);
        return NoContent();
    }
}
