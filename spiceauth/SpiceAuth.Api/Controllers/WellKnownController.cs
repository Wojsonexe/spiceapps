using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.Interfaces;

namespace SpiceAuth.Api.Controllers;

/// <summary>
/// OpenID Connect Discovery and JWKS endpoints.
/// These are used by resource servers to discover configuration and validate tokens.
/// </summary>
[ApiController]
[Route(".well-known")]
public class WellKnownController : ControllerBase
{
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _configuration;

    public WellKnownController(
        ITokenService tokenService,
        IConfiguration configuration)
    {
        _tokenService = tokenService;
        _configuration = configuration;
    }

    /// <summary>
    /// OpenID Connect Discovery endpoint.
    /// Returns metadata about the OAuth/OIDC server.
    /// </summary>
    [HttpGet("openid-configuration")]
    [Produces("application/json")]
    public IActionResult GetOpenIdConfiguration()
    {
        var issuer = _configuration["JwtSettings:Issuer"] 
                     ?? $"{Request.Scheme}://{Request.Host}";

        var config = new
        {
            issuer = issuer,
            authorization_endpoint = $"{issuer}/oauth/authorize",
            token_endpoint = $"{issuer}/oauth/token",
            userinfo_endpoint = $"{issuer}/oauth/userinfo",
            jwks_uri = $"{issuer}/.well-known/jwks.json",
            revocation_endpoint = $"{issuer}/oauth/revoke",
            scopes_supported = new[]
            {
                "openid", "profile", "email",
                "user:read", "user:write",
                "admin:approve", "admin:users", "admin:clients",
                "api:read", "api:write",
                "bot:commands"
            },
            response_types_supported = new[] { "code" },
            grant_types_supported = new[]
            {
                "authorization_code",
                "refresh_token",
                "client_credentials"
            },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            token_endpoint_auth_methods_supported = new[]
            {
                "client_secret_post",
                "client_secret_basic"
            },
            code_challenge_methods_supported = new[] { "S256", "plain" }
        };

        return Ok(config);
    }

    /// <summary>
    /// JWKS (JSON Web Key Set) endpoint.
    /// Returns public keys used to verify JWT signatures.
    /// Resource servers cache this and use it to validate tokens locally.
    /// </summary>
    [HttpGet("jwks.json")]
    [Produces("application/json")]
    [ResponseCache(Duration = 3600)] // Cache for 1 hour
    public IActionResult GetJwks()
    {
        var jwks = _tokenService.GetJwks();
        return Content(jwks, "application/json");
    }
}