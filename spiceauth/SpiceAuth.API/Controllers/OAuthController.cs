using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.OAuth;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Application.Services.OAuth;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("oauth")]
public sealed class OAuthController(
    IOAuthService oauthService,
    ILogger<OAuthController> logger) : ControllerBase
{
    private readonly IOAuthService _oauthService = oauthService;
    private readonly ILogger<OAuthController> _logger = logger;
    
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(request.GrantType))
                throw new OAuthException("invalid_request", "grant_type is required");

            return request.GrantType switch
            {
                "authorization_code" => Ok(await _oauthService.ExchangeAuthorizationCodeAsync(
                    request.Code!,
                    Guid.Parse(request.ClientId),
                    request.RedirectUri!,
                    request.CodeVerifier)),

                "refresh_token" => Ok(await _oauthService.RefreshTokenAsync(
                    request.RefreshToken!,
                    Guid.Parse(request.ClientId))),

                "client_credentials" => Ok(await _oauthService.ClientCredentialsAsync(
                    request.ClientId,
                    request.ClientSecret!)),

                _ => throw new OAuthException("unsupported_grant_type")
            };
        }
        catch (OAuthException ex)
        {
            return BadRequest(new OAuthError { Error = ex.Error, ErrorDescription = ex.ErrorDescription });
        }
    }

    /// <summary>
    /// OpenID Connect UserInfo Endpoint
    /// Returns claims about the authenticated user
    /// </summary>
    [HttpGet("userinfo")]
    [Authorize]
    [ProducesResponseType(typeof(object), 200)]
    [ProducesResponseType(401)]
    public async Task<ActionResult> UserInfo()
    {
        try
        {
            // Get subject from JWT claims
            var subClaim = User.FindFirst(ClaimTypes.NameIdentifier) ?? User.FindFirst("sub");
            
            if (subClaim == null)
            {
                _logger.LogWarning("UserInfo request without valid sub claim");
                return Unauthorized(new OAuthError
                {
                    Error = "invalid_token",
                    ErrorDescription = "Token does not contain a valid subject claim"
                });
            }

            var userId = Guid.Parse(subClaim.Value);
            var userInfo = await _oauthService.GetUserInfoAsync(userId);

            return Ok(userInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user info");
            return StatusCode(500, new OAuthError
            {
                Error = "server_error",
                ErrorDescription = "An error occurred retrieving user information"
            });
        }
    }

    /// <summary>
    /// OAuth 2.0 Token Introspection Endpoint (RFC 7662)
    /// </summary>
    [HttpPost("introspect")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(typeof(object), 200)]
    public async Task<ActionResult> Introspect(
        [FromForm(Name = "token")] string token,
        [FromForm(Name = "token_type_hint")] string? tokenTypeHint = null,
        [FromForm(Name = "client_id")] string? clientId = null,
        [FromForm(Name = "client_secret")] string? clientSecret = null)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return BadRequest(new OAuthError
                {
                    Error = "invalid_request",
                    ErrorDescription = "token parameter is required"
                });
            }

            var result = await _oauthService.IntrospectTokenAsync(
                token, 
                tokenTypeHint, 
                clientId, 
                clientSecret);

            return Ok(result);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Token introspection unauthorized");
            return Unauthorized(new OAuthError
            {
                Error = "invalid_client",
                ErrorDescription = "Client authentication failed"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token introspection");
            return Ok(new { active = false });
        }
    }

    /// <summary>
    /// OAuth 2.0 Token Revocation Endpoint (RFC 7009)
    /// </summary>
    [HttpPost("revoke")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(200)]
    [ProducesResponseType(typeof(OAuthError), 400)]
    public async Task<ActionResult> Revoke(
        [FromForm(Name = "token")] string token,
        [FromForm(Name = "token_type_hint")] string? tokenTypeHint = null,
        [FromForm(Name = "client_id")] string? clientId = null,
        [FromForm(Name = "client_secret")] string? clientSecret = null)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return BadRequest(new OAuthError
                {
                    Error = "invalid_request",
                    ErrorDescription = "token parameter is required"
                });
            }

            await _oauthService.RevokeTokenAsync(
                token, 
                tokenTypeHint, 
                clientId, 
                clientSecret);

            // RFC 7009: The authorization server responds with HTTP status code 200
            // if the token has been revoked successfully or if the client 
            // submitted an invalid token
            return Ok();
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(ex, "Token revocation unauthorized");
            return Unauthorized(new OAuthError
            {
                Error = "invalid_client",
                ErrorDescription = "Client authentication failed"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token revocation");
            // Still return 200 per RFC 7009
            return Ok();
        }
    }
}