using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.API.Controllers;

/// <summary>
/// Test endpoints for development (DISABLED IN PRODUCTION)
/// </summary>
[ApiController]
[Route("api/test")]
public class TestController(
    IOAuthService oauthService,
    DbContext context,
    IWebHostEnvironment environment,
    ILogger<TestController> logger) : ControllerBase
{
    private readonly IOAuthService _oauthService = oauthService;
    private readonly DbContext _context = context;
    private readonly IWebHostEnvironment _environment = environment;
    private readonly ILogger<TestController> _logger = logger;

    /// <summary>
    /// Generate test authorization code (DEVELOPMENT ONLY)
    /// </summary>
    [HttpPost("generate-auth-code")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<object>> GenerateAuthCode(
        [FromQuery] string? email = "admin@spiceauth.com")
    {
        // 🔒 BLOCK IN PRODUCTION
        if (!_environment.IsDevelopment())
        {
            _logger.LogWarning("Test endpoint accessed in non-development environment");
            return StatusCode(403, new { error = "This endpoint is only available in development" });
        }

        // Get test user
        var user = await _context.Set<ApplicationUser>()
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
        {
            return NotFound(new { error = $"User not found: {email}" });
        }

        // Get test client
        var client = await _oauthService.GetClientByClientIdAsync("testmobileapp");
        
        if (client == null)
        {
            return NotFound(new { error = "Test client 'testmobileapp' not found" });
        }

        // Generate PKCE challenge (for testing)
        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        // Create authorization code
        var authCode = await _oauthService.CreateAuthorizationCodeAsync(
            userId: user.Id,
            clientId: client.Id,
            redirectUri: "http://localhost:3000/callback",
            scope: "openid profile email offline_access",
            codeChallenge: codeChallenge,
            codeChallengeMethod: "S256",
            nonce: Guid.NewGuid().ToString()
        );

        _logger.LogInformation("Test authorization code generated for user {Email}", email);

        return Ok(new
        {
            message = "✅ Test authorization code generated",
            code = authCode.Code,
            code_verifier = codeVerifier,
            code_challenge = codeChallenge,
            user_id = user.Id,
            user_email = user.Email,
            client_id = client.ClientId,
            redirect_uri = authCode.RedirectUri,
            expires_at = authCode.ExpiresAt,
            usage = new
            {
                step1 = "POST /oauth/token",
                parameters = new
                {
                    grant_type = "authorization_code",
                    code = authCode.Code,
                    redirect_uri = "http://localhost:3000/callback",
                    client_id = "testmobileapp",
                    client_secret = "testsecret123",
                    code_verifier = codeVerifier
                }
            }
        });
    }

    /// <summary>
    /// Get test client info (DEVELOPMENT ONLY)
    /// </summary>
    [HttpGet("client-info")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<object>> GetClientInfo()
    {
        // 🔒 BLOCK IN PRODUCTION
        if (!_environment.IsDevelopment())
        {
            return StatusCode(403, new { error = "This endpoint is only available in development" });
        }

        var client = await _oauthService.GetClientByClientIdAsync("testmobileapp");
        
        if (client == null)
        {
            return NotFound(new { error = "Test client not found" });
        }

        return Ok(new
        {
            client_id = client.ClientId,
            client_secret = "testsecret123",
            name = client.Name,
            redirect_uris = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.RedirectUris),
            allowed_scopes = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.AllowedScopes),
            requires_pkce = client.RequirePkce,
            requires_consent = client.RequireConsent
        });
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = new byte[32];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }

    private static string GenerateCodeChallenge(string codeVerifier)
    {
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier));
        return Convert.ToBase64String(hash)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
