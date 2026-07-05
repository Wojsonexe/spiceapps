using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.Services.Token;

namespace SpiceAuth.API.Controllers;

/// <summary>
/// OpenID Connect Discovery and JWKS endpoints (RFC 8414)
/// </summary>
[ApiController]
[Route("/.well-known")]
[AllowAnonymous]
public class WellKnownController(
    ITokenService tokenService,
    IConfiguration configuration,
    ILogger<WellKnownController> logger) : ControllerBase
{
    private readonly ITokenService _tokenService = tokenService;
    private readonly IConfiguration _configuration = configuration;
    private readonly ILogger<WellKnownController> _logger = logger;

    /// <summary>
    /// OpenID Connect Discovery Document (RFC 8414)
    /// </summary>
    [HttpGet("openid-configuration")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any)]
    public ActionResult<object> GetOpenIdConfiguration()
    {
        var requestBase = $"{Request.Scheme}://{Request.Host}";
        var issuer = _configuration["Jwt:Issuer"] ?? requestBase;

        _logger.LogDebug("OpenID configuration requested from {IP}",
            HttpContext.Connection.RemoteIpAddress);

        var config = new
        {
            issuer,
            authorization_endpoint = $"{issuer}/oauth/authorize",
            token_endpoint = $"{issuer}/oauth/token",
            userinfo_endpoint = $"{issuer}/oauth/userinfo",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            registration_endpoint = $"{issuer}/api/clients/register",
            revocation_endpoint = $"{issuer}/oauth/revoke",
            introspection_endpoint = $"{issuer}/oauth/introspect",
            end_session_endpoint = $"{issuer}/oauth/account/logout",
            
            response_types_supported = new[]
            {
                "code"
            },
            
            response_modes_supported = new[]
            {
                "query",
                "fragment"
            },
            
            grant_types_supported = new[]
            {
                "authorization_code",
                "refresh_token"
            },
            
            subject_types_supported = new[] { "public" },
            
            id_token_signing_alg_values_supported = new[] { "RS256" },
            
            scopes_supported = new[]
            {
                "openid",
                "profile",
                "email",
                "offline_access"
            },
            
            token_endpoint_auth_methods_supported = new[]
            {
                "client_secret_post",
                "client_secret_basic",
                "none"
            },
            
            claims_supported = new[]
            {
                "sub",
                "email",
                "email_verified",
                "name",
                "preferred_username",
                "given_name",
                "family_name",
                "picture",
                "iss",
                "aud",
                "exp",
                "iat",
                "nbf",
                "jti",
                "sid",
                "nonce",
                "roles"
            },
            
            code_challenge_methods_supported = new[] { "S256" },

            backchannel_logout_supported         = true,
            backchannel_logout_session_supported = true,

            service_documentation = $"{issuer}/docs",

            ui_locales_supported = new[] { "en-US", "pl-PL" },

            op_policy_uri = $"{issuer}/privacy",
            op_tos_uri    = $"{issuer}/terms"
        };

        return Ok(config);
    }

    /// <summary>
    /// JSON Web Key Set (JWKS) - RFC 7517
    /// </summary>
    [HttpGet("jwks.json")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ResponseCache(Duration = 3600, Location = ResponseCacheLocation.Any, VaryByHeader = "User-Agent")]
    public async Task<ActionResult<object>> GetJwks()
    {
        try
        {
            _logger.LogDebug("JWKS requested from {IP}", 
                HttpContext.Connection.RemoteIpAddress);
            
            var jwks = await _tokenService.GetJwksAsync();
            
            return Ok(jwks);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving JWKS");
            return StatusCode(500, new { error = "Unable to retrieve public keys" });
        }
    }
}
