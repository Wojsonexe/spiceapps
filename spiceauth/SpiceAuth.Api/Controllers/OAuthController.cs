using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.Requests;
using SpiceAuth.Application.DTOs.Responses;
using SpiceAuth.Application.Interfaces;
using SpiceAuth.Domain.Enums;
using SpiceAuth.Infrastructure.Extensions;

namespace SpiceAuth.Api.Controllers;

/// <summary>
/// OAuth 2.0 / OIDC endpoints.
/// Handles token generation, authorization, and revocation.
/// </summary>
[ApiController]
[Route("oauth")]
public class OAuthController : ControllerBase
{
    private readonly ITokenService _tokenService;
    private readonly IClientService _clientService;
    private readonly ILogger<OAuthController> _logger;

    public OAuthController(
        ITokenService tokenService,
        IClientService clientService,
        ILogger<OAuthController> logger)
    {
        _tokenService = tokenService;
        _clientService = clientService;
        _logger = logger;
    }

    /// <summary>
    /// OAuth 2.0 Token Endpoint (RFC 6749).
    /// Supports: client_credentials, authorization_code, refresh_token.
    /// </summary>
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    public async Task<IActionResult> Token([FromForm] TokenRequest request)
    {
        _logger.LogInformation("Token request: grant_type={GrantType}, client_id={ClientId}", 
            request.GrantType, request.ClientId);

        // Validate client credentials
        var client = await _clientService.ValidateClientCredentialsAsync(
            request.ClientId, 
            request.ClientSecret ?? string.Empty);

        if (client == null)
        {
            return Unauthorized(new ErrorResponse
            {
                Error = OAuthErrors.InvalidClient,
                ErrorDescription = "Invalid client credentials"
            });
        }

        // Route to appropriate grant type handler
        return request.GrantType?.ToLowerInvariant() switch
        {
            "client_credentials" => await HandleClientCredentials(client, request),
            "authorization_code" => HandleAuthorizationCode(client, request),
            "refresh_token" => HandleRefreshToken(client, request),
            _ => BadRequest(new ErrorResponse
            {
                Error = OAuthErrors.UnsupportedGrantType,
                ErrorDescription = $"Grant type '{request.GrantType}' is not supported"
            })
        };
    }

    /// <summary>
    /// Handle client_credentials grant (RFC 6749 Section 4.4).
    /// Used for machine-to-machine (M2M) authentication.
    /// </summary>
    private async Task<IActionResult> HandleClientCredentials(
        Domain.Entities.OAuthClient client, 
        TokenRequest request)
    {
        // Service clients only
        if (client.ClientType != ClientType.Service)
        {
            return BadRequest(new ErrorResponse
            {
                Error = OAuthErrors.UnauthorizedClient,
                ErrorDescription = "Client is not authorized for client_credentials grant"
            });
        }

        // Validate scope
        var requestedScope = request.Scope ?? string.Join(' ', client.GetAllowedScopes());
        if (!_clientService.IsClientAllowedScope(client, requestedScope))
        {
            return BadRequest(new ErrorResponse
            {
                Error = OAuthErrors.InvalidScope,
                ErrorDescription = "Requested scope is not allowed for this client"
            });
        }

        // Generate token
        var accessToken = _tokenService.GenerateClientCredentialsToken(
            client.ClientId, 
            requestedScope);

        _logger.LogInformation("Generated client_credentials token for {ClientId}", client.ClientId);

        return Ok(new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = client.AccessTokenLifetime,
            Scope = requestedScope
        });
    }

    /// <summary>
    /// Handle authorization_code grant (RFC 6749 Section 4.1).
    /// TODO: Implement in next phase.
    /// </summary>
    private IActionResult HandleAuthorizationCode(
        Domain.Entities.OAuthClient client, 
        TokenRequest request)
    {
        // Placeholder - implement in Phase 3
        return BadRequest(new ErrorResponse
        {
            Error = OAuthErrors.UnsupportedGrantType,
            ErrorDescription = "authorization_code grant not yet implemented"
        });
    }

    /// <summary>
    /// Handle refresh_token grant (RFC 6749 Section 6).
    /// TODO: Implement in next phase.
    /// </summary>
    private IActionResult HandleRefreshToken(
        Domain.Entities.OAuthClient client, 
        TokenRequest request)
    {
        // Placeholder - implement in Phase 3
        return BadRequest(new ErrorResponse
        {
            Error = OAuthErrors.UnsupportedGrantType,
            ErrorDescription = "refresh_token grant not yet implemented"
        });
    }
}