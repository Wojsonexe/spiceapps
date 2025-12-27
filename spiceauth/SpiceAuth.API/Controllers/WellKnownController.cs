using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.Services.Token;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route(".well-known")]
public class WellKnownController(
    ITokenService tokenService,
    IConfiguration configuration) : ControllerBase
{
    private readonly ITokenService _tokenService = tokenService;
    private readonly IConfiguration _configuration = configuration;

    /// <summary>
    /// OpenID Connect Discovery Document
    /// </summary>
    [HttpGet("openid-configuration")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public ActionResult<object> GetOpenIdConfiguration()
    {
        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        var issuer = _configuration["Jwt:Issuer"] ?? baseUrl;

        var config = new
        {
            issuer,
            authorization_endpoint = $"{baseUrl}/oauth/authorize",
            token_endpoint = $"{baseUrl}/oauth/token",
            userinfo_endpoint = $"{baseUrl}/oauth/userinfo",
            jwks_uri = $"{baseUrl}/.well-known/jwks.json",
            registration_endpoint = $"{baseUrl}/oauth/register",
            revocation_endpoint = $"{baseUrl}/oauth/revoke",
            introspection_endpoint = $"{baseUrl}/oauth/introspect",
            
            response_types_supported = new[]
            {
                "code",
                "token",
                "id_token",
                "code token",
                "code id_token",
                "token id_token",
                "code token id_token"
            },
            
            response_modes_supported = new[]
            {
                "query",
                "fragment",
                "form_post"
            },
            
            grant_types_supported = new[]
            {
                "authorization_code",
                "refresh_token",
                "client_credentials"
            },
            
            subject_types_supported = new[] { "public" },
            
            id_token_signing_alg_values_supported = new[] { "RS256" },
            
            scopes_supported = new[]
            {
                "openid",
                "profile",
                "email",
                "offline_access",
                "read:posts",
                "write:posts",
                "admin:users",
                "org:read",
                "org:write",
                "org:manage"
            },
            
            token_endpoint_auth_methods_supported = new[]
            {
                "client_secret_basic",
                "client_secret_post",
                "none" // For PKCE public clients
            },
            
            claims_supported = new[]
            {
                "sub",
                "email",
                "email_verified",
                "preferred_username",
                "given_name",
                "family_name",
                "picture",
                "iss",
                "aud",
                "exp",
                "iat",
                "nbf"
            },
            
            code_challenge_methods_supported = new[] { "S256" },
            
            service_documentation = $"{baseUrl}/docs",
            
            ui_locales_supported = new[] { "en-US", "pl-PL" }
        };

        return Ok(config);
    }

    /// <summary>
    /// JSON Web Key Set (JWKS)
    /// </summary>
    [HttpGet("jwks.json")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ResponseCache(Duration = 3600)] // Cache for 1 hour
    public async Task<ActionResult<object>> GetJwks()
    {
        var jwks = await _tokenService.GetJwksAsync();
        return Ok(jwks);
    }
}