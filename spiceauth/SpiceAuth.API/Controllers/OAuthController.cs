using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.OAuth;
using System.Text.Json;
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

    // ══════════════════════════════════════════════════════════════════
    // AUTHORIZATION ENDPOINT (RFC 6749 Section 3.1)
    // ══════════════════════════════════════════════════════════════════

    /// <summary>
    /// OAuth 2.1 Authorization Endpoint
    /// Step 1: Client redirects user here to get authorization
    /// </summary>
    [HttpGet("authorize")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Authorize(
        [FromQuery(Name = "response_type")] string? responseType,
        [FromQuery(Name = "client_id")] string? clientId,
        [FromQuery(Name = "redirect_uri")] string? redirectUri,
        [FromQuery] string? scope,
        [FromQuery] string? state,
        [FromQuery(Name = "code_challenge")] string? codeChallenge,
        [FromQuery(Name = "code_challenge_method")]
        string? codeChallengeMethod,
        [FromQuery] string? nonce,
        [FromQuery] string? prompt)
    {
        try
        {
            // Validate required parameters
            if (string.IsNullOrWhiteSpace(responseType))
                return BadRequest(new { error = "invalid_request", error_description = "response_type is required" });

            if (responseType != "code")
                return BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' is supported" });

            if (string.IsNullOrWhiteSpace(clientId))
                return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });

            if (string.IsNullOrWhiteSpace(redirectUri))
                return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });

            var client = await _oauthService.GetClientByClientIdAsync(clientId);
            if (client == null || !client.IsActive)
            {
                return BadRequest(new { error = "invalid_client", error_description = "Client not found or inactive" });
            }

            // Validate redirect URI
            if (!await _oauthService.ValidateRedirectUriAsync(client.Id, redirectUri))
            {
                return BadRequest(new { error = "invalid_request", error_description = "Invalid redirect_uri" });
            }

            // Validate PKCE if required
            if (client.RequirePkce)
            {
                if (string.IsNullOrWhiteSpace(codeChallenge))
                {
                    return RedirectToError(redirectUri, "invalid_request", "code_challenge is required for this client", state);
                }

                if (codeChallengeMethod != "S256")
                {
                    return RedirectToError(redirectUri, "invalid_request", "code_challenge_method must be S256", state);
                }
            }
            
            // TODO: Check if user is authenticated
            // For now, we'll simulate that user needs to login
            var userId = GetAuthenticatedUserId();
                
            if (userId == null)
            {
                // Redirect to login page with return URL
                var returnUrl = HttpContext.Request.QueryString.ToString();
                return Redirect($"/login?returnUrl={Uri.EscapeDataString("/oauth/authorize" + returnUrl)}");
            }
            
            // Check if user has already consented
            var hasConsented = await _oauthService.HasUserConsentedAsync(
                userId.Value, 
                client.Id, 
                scope ?? "openid profile");

            if (!hasConsented && client.RequireConsent && prompt != "none")
            {
                // Show consent screen
                return await ShowConsentScreen(
                    userId.Value,
                    client,
                    redirectUri,
                    scope ?? "openid profile",
                    state,
                    codeChallenge,
                    codeChallengeMethod,
                    nonce);
            }
            
            // Generate authorization code
            var authCode = await _oauthService.CreateAuthorizationCodeAsync(
                userId.Value,
                client.Id,
                redirectUri,
                scope ?? "openid profile",
                codeChallenge,
                codeChallengeMethod,
                nonce);

            // Redirect back to client with code
            var callbackUri = BuildCallbackUri(redirectUri, authCode.Code, state);
                
            _logger.LogInformation(
                "Authorization code issued for user {UserId}, client {ClientId}", 
                userId.Value, 
                client.Id);

            return Redirect(callbackUri); 
        } catch (Exception ex)
        {
            _logger.LogError(ex, "Error in authorize endpoint");
            
            if (!string.IsNullOrWhiteSpace(redirectUri))
            {
                return RedirectToError(redirectUri, "server_error", "An error occurred", state);
            }
            
            return BadRequest(new { error = "server_error", error_description = "An error occurred" });
        }
    }
    
    /// <summary>
    /// POST endpoint for consent - user grants permission
    /// </summary>
    [HttpPost("authorize/consent")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> GrantConsent([FromForm] ConsentRequest request)
    {
        try
        {
            // TODO: Validate user is authenticated
            var userId = GetAuthenticatedUserId();
            if (userId == null)
            {
                return Redirect("/login");
            }

            var client = await _oauthService.GetClientByClientIdAsync(request.ClientId);
            if (client == null)
            {
                return BadRequest(new { error = "invalid_client" });
            }

            if (request.Approved)
            {
                // Grant consent
                await _oauthService.GrantConsentAsync(userId.Value, client.Id, request.Scope);

                // Generate authorization code
                var authCode = await _oauthService.CreateAuthorizationCodeAsync(
                    userId.Value,
                    client.Id,
                    request.RedirectUri,
                    request.Scope,
                    request.CodeChallenge,
                    request.CodeChallengeMethod,
                    request.Nonce);

                // Redirect with code
                var callbackUri = BuildCallbackUri(request.RedirectUri, authCode.Code, request.State);
                return Redirect(callbackUri);
            }
            else
            {
                // User denied consent
                return RedirectToError(request.RedirectUri, "access_denied", "User denied consent", request.State);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing consent");
            return RedirectToError(request.RedirectUri, "server_error", "An error occurred", request.State);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // TOKEN ENDPOINT (RFC 6749 Section 3.2)
    // ══════════════════════════════════════════════════════════════════

    /// <summary>
    /// OAuth 2.1 Token Endpoint
    /// Step 2: Client exchanges authorization code for tokens
    /// </summary>
    /// [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<TokenResponse>> Token(
        [FromForm(Name = "grant_type")] string? grantType,
        [FromForm] string? code,
        [FromForm(Name = "redirect_uri")] string? redirectUri,
        [FromForm(Name = "client_id")] string? clientId,
        [FromForm(Name = "client_secret")] string? clientSecret,
        [FromForm(Name = "code_verifier")] string? codeVerifier,
        [FromForm(Name = "refresh_token")] string? refreshToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(grantType))
            {
                return BadRequest(new OAuthErrorResponse("invalid_request", "grant_type is required"));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                return BadRequest(new OAuthErrorResponse("invalid_request", "client_id is required"));
            }

            var client = await _oauthService.GetClientByClientIdAsync(clientId);
            if (client == null)
            {
                return BadRequest(new OAuthErrorResponse("invalid_client", "Client not found"));
            }

            return grantType switch
            {
                "authorization_code" => await HandleAuthorizationCodeGrant(
                    code, redirectUri, clientId, clientSecret, codeVerifier, client.Id),

                "refresh_token" => await HandleRefreshTokenGrant(
                    refreshToken, clientId, clientSecret, client.Id),

                "client_credentials" => await HandleClientCredentialsGrant(
                    clientId, clientSecret),

                _ => BadRequest(new OAuthErrorResponse("unsupported_grant_type",
                    $"Grant type '{grantType}' is not supported"))
            };
        }
        catch (OAuthException ex)
        {
            return BadRequest(new OAuthErrorResponse(ex.Error, ex.ErrorDescription));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in token endpoint");
            return BadRequest(new OAuthErrorResponse("server_error", "An error occurred"));
        }
    }
    
    // ══════════════════════════════════════════════════════════════════
    // TOKEN INTROSPECTION (RFC 7662)
    // ══════════════════════════════════════════════════════════════════
    
    /// <summary>
    /// Token Introspection Endpoint
    /// Allows resource servers to validate tokens
    /// </summary>
    [HttpPost("introspect")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<object>> Introspect(
        [FromForm] string? token,
        [FromForm(Name = "token_type_hint")] string? tokenTypeHint,
        [FromForm(Name = "client_id")] string? clientId,
        [FromForm(Name = "client_secret")] string? clientSecret)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return BadRequest(new { error = "invalid_request", error_description = "token is required" });
            }

            var result = await _oauthService.IntrospectTokenAsync(
                token, 
                tokenTypeHint, 
                clientId, 
                clientSecret);

            return Ok(result);
        }
        catch (OAuthException ex)
        {
            return BadRequest(new { error = ex.Error, error_description = ex.ErrorDescription });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in introspect endpoint");
            return Ok(new { active = false });
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // TOKEN REVOCATION (RFC 7009)
    // ══════════════════════════════════════════════════════════════════
    
    /// <summary>
    /// Token Revocation Endpoint
    /// Allows clients to revoke tokens
    /// </summary>
    [HttpPost("revoke")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Revoke(
        [FromForm] string? token,
        [FromForm(Name = "token_type_hint")] string? tokenTypeHint,
        [FromForm(Name = "client_id")] string? clientId,
        [FromForm(Name = "client_secret")] string? clientSecret)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return BadRequest(new { error = "invalid_request", error_description = "token is required" });
            }

            await _oauthService.RevokeTokenAsync(
                token, 
                tokenTypeHint, 
                clientId, 
                clientSecret);

            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in revoke endpoint");
            // RFC 7009: The authorization server responds with HTTP status code 200
            // even if the token is invalid
            return Ok();
        }
    }
    
    // ══════════════════════════════════════════════════════════════════
    // HELPER METHODS
    // ══════════════════════════════════════════════════════════════════

    private async Task<ActionResult<TokenResponse>> HandleAuthorizationCodeGrant(
        string? code,
        string? redirectUri,
        string? clientId,
        string? clientSecret,
        string? codeVerifier,
        Guid clientGuid)
    {
        if (string.IsNullOrWhiteSpace(code))
            return BadRequest(new OAuthErrorResponse("invalid_request", "code is required"));

        if (string.IsNullOrWhiteSpace(redirectUri))
            return BadRequest(new OAuthErrorResponse("invalid_request", "redirect_uri is required"));

        // Validate client secret for confidential clients
        var client = await _oauthService.GetClientByIdAsync(clientGuid);
        if (client?.ClientType == Core.Enums.OAuthClientType.Confidential)
        {
            if (string.IsNullOrWhiteSpace(clientSecret))
                return BadRequest(new OAuthErrorResponse("invalid_client", "client_secret is required"));

            if (!await _oauthService.ValidateClientAsync(clientId!, clientSecret))
                return BadRequest(new OAuthErrorResponse("invalid_client", "Invalid client credentials"));
        }

        var tokenResponse = await _oauthService.ExchangeAuthorizationCodeAsync(
            code,
            clientGuid,
            redirectUri,
            codeVerifier);

        return Ok(tokenResponse);
    }

    private async Task<ActionResult<TokenResponse>> HandleRefreshTokenGrant(
        string? refreshToken,
        string? clientId,
        string? clientSecret,
        Guid clientGuid)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
            return BadRequest(new OAuthErrorResponse("invalid_request", "refresh_token is required"));

        // Validate client credentials
        if (!await _oauthService.ValidateClientAsync(clientId!, clientSecret))
            return BadRequest(new OAuthErrorResponse("invalid_client", "Invalid client credentials"));

        var tokenResponse = await _oauthService.RefreshTokenAsync(refreshToken, clientGuid);
        return Ok(tokenResponse);
    }

    private async Task<ActionResult<TokenResponse>> HandleClientCredentialsGrant(
        string? clientId,
        string? clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientSecret))
            return BadRequest(new OAuthErrorResponse("invalid_request", "client_secret is required"));

        var tokenResponse = await _oauthService.ClientCredentialsAsync(clientId!, clientSecret);
        return Ok(tokenResponse);
    }

    private async Task<IActionResult> ShowConsentScreen(
        Guid userId,
        Core.Entities.OAuth.OAuthClient client,
        string redirectUri,
        string scope,
        string? state,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? nonce)
    {
        // Return HTML consent screen
        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var allowedScopes = JsonSerializer.Deserialize<List<string>>(client.AllowedScopes) ?? new List<string>();
        
        var html = GenerateConsentHtml(
            client.Name,
            client.Description ?? "",
            scopes.Where(s => allowedScopes.Contains(s)).ToArray(),
            client.ClientId,
            redirectUri,
            scope,
            state ?? "",
            codeChallenge ?? "",
            codeChallengeMethod ?? "",
            nonce ?? "");

        return Content(html, "text/html");
    }

    private static string BuildCallbackUri(string redirectUri, string code, string? state)
    {
        var builder = new UriBuilder(redirectUri);
        var query = System.Web.HttpUtility.ParseQueryString(builder.Query);
        
        query["code"] = code;
        if (!string.IsNullOrWhiteSpace(state))
        {
            query["state"] = state;
        }

        builder.Query = query.ToString();
        return builder.ToString();
    }

    private IActionResult RedirectToError(string redirectUri, string error, string? errorDescription, string? state)
    {
        var builder = new UriBuilder(redirectUri);
        var query = System.Web.HttpUtility.ParseQueryString(builder.Query);
        
        query["error"] = error;
        if (!string.IsNullOrWhiteSpace(errorDescription))
        {
            query["error_description"] = errorDescription;
        }
        if (!string.IsNullOrWhiteSpace(state))
        {
            query["state"] = state;
        }

        builder.Query = query.ToString();
        return Redirect(builder.ToString());
    }

    private Guid? GetAuthenticatedUserId()
    {
        // TODO: Get from JWT claims when authentication is implemented
        // For now, return null to simulate unauthenticated user
        
        // var userIdClaim = User.FindFirst("sub")?.Value;
        // if (Guid.TryParse(userIdClaim, out var userId))
        // {
        //     return userId;
        // }
        
        return null;
    }

    private static string GenerateConsentHtml(
        string clientName,
        string clientDescription,
        string[] scopes,
        string clientId,
        string redirectUri,
        string scope,
        string state,
        string codeChallenge,
        string codeChallengeMethod,
        string nonce)
    {
        var scopeDescriptions = new Dictionary<string, string>
        {
            { "openid", "Access your basic profile information" },
            { "profile", "Access your full profile (name, picture, etc.)" },
            { "email", "Access your email address" },
            { "offline_access", "Keep access to your data even when you're not using the app" }
        };

        var scopeItems = string.Join("", scopes.Select(s => 
            $"<li><strong>{s}</strong>: {scopeDescriptions.GetValueOrDefault(s, "Access your data")}</li>"));

        return $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1"">
    <title>Authorization Required - SpiceAuth</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 480px;
            width: 100%;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 32px;
            text-align: center;
        }}
        .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .header p {{ opacity: 0.9; font-size: 14px; }}
        .content {{
            padding: 32px;
        }}
        .client-info {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
        }}
        .client-name {{
            font-size: 20px;
            font-weight: 600;
            color: #212529;
            margin-bottom: 4px;
        }}
        .client-desc {{
            color: #6c757d;
            font-size: 14px;
        }}
        .permissions {{
            margin: 24px 0;
        }}
        .permissions h3 {{
            font-size: 16px;
            color: #212529;
            margin-bottom: 12px;
        }}
        .permissions ul {{
            list-style: none;
            padding: 0;
        }}
        .permissions li {{
            padding: 12px;
            background: #f8f9fa;
            border-radius: 6px;
            margin-bottom: 8px;
            font-size: 14px;
            line-height: 1.5;
        }}
        .permissions strong {{
            color: #667eea;
            text-transform: capitalize;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px;
            border-radius: 4px;
            margin: 16px 0;
            font-size: 13px;
            color: #856404;
        }}
        .actions {{
            display: flex;
            gap: 12px;
            margin-top: 24px;
        }}
        button {{
            flex: 1;
            padding: 14px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn-approve {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .btn-approve:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }}
        .btn-deny {{
            background: #6c757d;
            color: white;
        }}
        .btn-deny:hover {{
            background: #5a6268;
        }}
    </style>
</head>
<body>
    <div class=""container"">
        <div class=""header"">
            <h1>🔐 Authorization Required</h1>
            <p>SpiceAuth</p>
        </div>
        <div class=""content"">
            <div class=""client-info"">
                <div class=""client-name"">{clientName}</div>
                {(string.IsNullOrWhiteSpace(clientDescription) ? "" : $"<div class=\"client-desc\">{clientDescription}</div>")}
            </div>
            
            <p style=""margin-bottom: 16px; color: #495057;"">
                <strong>{clientName}</strong> is requesting access to your account.
            </p>
            
            <div class=""permissions"">
                <h3>This application will be able to:</h3>
                <ul>
                    {scopeItems}
                </ul>
            </div>
            
            <div class=""warning"">
                ⚠️ Only authorize applications you trust. You can revoke access at any time from your account settings.
            </div>
            
            <form method=""POST"" action=""/oauth/authorize/consent"">
                <input type=""hidden"" name=""clientId"" value=""{clientId}"" />
                <input type=""hidden"" name=""redirectUri"" value=""{redirectUri}"" />
                <input type=""hidden"" name=""scope"" value=""{scope}"" />
                <input type=""hidden"" name=""state"" value=""{state}"" />
                <input type=""hidden"" name=""codeChallenge"" value=""{codeChallenge}"" />
                <input type=""hidden"" name=""codeChallengeMethod"" value=""{codeChallengeMethod}"" />
                <input type=""hidden"" name=""nonce"" value=""{nonce}"" />
                
                <div class=""actions"">
                    <button type=""submit"" name=""approved"" value=""false"" class=""btn-deny"">
                        Deny
                    </button>
                    <button type=""submit"" name=""approved"" value=""true"" class=""btn-approve"">
                        Authorize
                    </button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>";
    }
}
