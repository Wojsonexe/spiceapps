using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TestController(
    IOAuthService oauthService,
    DbContext context) : ControllerBase
{
    private readonly IOAuthService _oauthService = oauthService;
    private readonly DbContext _context = context;

    /// <summary>
    /// Generate test authorization code (DEVELOPMENT ONLY)
    /// </summary>
    [HttpPost("generate-auth-code")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<object>> GenerateAuthCode(
        [FromQuery] string? email = "test@example.com")
    {
        // Get test user
        var user = await _context.Set<User>()
            .FirstOrDefaultAsync(u => u.Email == email);

        if (user == null)
        {
            return NotFound(new { error = "Test user not found" });
        }

        // Get test client
        var client = await _oauthService.GetClientByClientIdAsync("test-client");
        
        if (client == null)
        {
            return NotFound(new { error = "Test client not found" });
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

        return Ok(new
        {
            message = "Test authorization code generated",
            code = authCode.Code,
            code_verifier = codeVerifier,
            code_challenge = codeChallenge,
            user_id = user.Id,
            client_id = client.ClientId,
            redirect_uri = authCode.RedirectUri,
            expires_at = authCode.ExpiresAt,
            usage = new
            {
                step1 = "Use this code in POST /oauth/token",
                step2 = "Set grant_type=authorization_code",
                step3 = $"Set code={authCode.Code}",
                step4 = "Set redirect_uri=http://localhost:3000/callback",
                step5 = "Set client_id=test-client",
                step6 = $"Set code_verifier={codeVerifier}"
            }
        });
    }

    /// <summary>
    /// Get test client info
    /// </summary>
    [HttpGet("client-info")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<object>> GetClientInfo()
    {
        var client = await _oauthService.GetClientByClientIdAsync("test-client");
        
        if (client == null)
        {
            return NotFound(new { error = "Test client not found" });
        }

        return Ok(new
        {
            client_id = client.ClientId,
            client_secret = "test-secret",
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