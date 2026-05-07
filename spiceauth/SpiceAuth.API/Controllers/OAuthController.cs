using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Json;
using System.Web;
using SpiceAuth.API.Metrics;
using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Application.Services.RateLimit;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.API.Controllers;

/// <summary>OAuth 2.1 / OIDC endpoints: authorization, token exchange, revocation, introspection, logout.</summary>
[ApiController]
[Route("/api/[controller]")]
[Authorize(AuthenticationSchemes = "Identity.Application")]
public sealed class OAuthController : ControllerBase
{
    private readonly IOAuthService _oauthService;
    private readonly IFederationService _federation;
    private readonly IRateLimitService _rateLimiter;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IAuditService _auditService;
    private readonly ILogger<OAuthController> _logger;
    private readonly IConfiguration _configuration;
    private readonly SpiceAuthMetrics _metrics;

    public OAuthController(
        IOAuthService oauthService,
        IFederationService federation,
        IRateLimitService rateLimiter,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IAuditService auditService,
        ILogger<OAuthController> logger,
        IConfiguration configuration,
        SpiceAuthMetrics metrics)
    {
        _oauthService  = oauthService;
        _federation    = federation;
        _rateLimiter   = rateLimiter;
        _userManager   = userManager;
        _signInManager = signInManager;
        _auditService  = auditService;
        _logger        = logger;
        _configuration = configuration;
        _metrics       = metrics;
    }

    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    private string Ua() => HttpContext.Request.Headers.UserAgent.ToString();

    #region LOGIN ENDPOINTS

    [HttpGet("account/login")]
    [AllowAnonymous]
    public IActionResult Login([FromQuery] string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(returnUrl) && !returnUrl.StartsWith("/"))
        {
            _logger.LogWarning("Invalid returnUrl rejected: {ReturnUrl}", returnUrl);
            returnUrl = null;
        }

        var frontendUrl = _configuration["App:FrontendUrl"] ?? "http://localhost:3002";
        var loginUrl = string.IsNullOrEmpty(returnUrl)
            ? $"{frontendUrl}/login"
            : $"{frontendUrl}/login?returnUrl={Uri.EscapeDataString(returnUrl)}";

        return Redirect(loginUrl);
    }

    [HttpPost("account/login")]
    [AllowAnonymous]
    public async Task<IActionResult> LoginPost(
        [FromForm] LoginModel model,
        [FromQuery] string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(returnUrl) && !returnUrl.StartsWith("/"))
        {
            _logger.LogWarning("Invalid returnUrl rejected: {ReturnUrl}", returnUrl);
            returnUrl = null;
        }

        var clientIp = Ip();

        if (_rateLimiter.IsBlocked("login", clientIp))
        {
            _logger.LogWarning("Login rate limit exceeded for IP: {IP}", clientIp);

            await _auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: model.Email,
                resourceType: "Auth",
                success: false,
                failureReason: "Rate limit exceeded",
                ipAddress: clientIp,
                userAgent: Ua());

            return Content(LoginPage(returnUrl,
                "Zbyt wiele prób logowania. Spróbuj ponownie za kilka minut."), "text/html");
        }

        if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
            return Content(LoginPage(returnUrl, "Email i hasło są wymagane."), "text/html");

        var user = await _userManager.FindByEmailAsync(model.Email);

        if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
        {
            _rateLimiter.RecordFailure("login", clientIp);

            await _auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: model.Email,
                resourceType: "Auth",
                success: false,
                failureReason: "Invalid credentials",
                ipAddress: clientIp,
                userAgent: Ua());

            _logger.LogWarning("Failed login attempt for {Email} from {IP}", model.Email, clientIp);
            return Content(LoginPage(returnUrl, "Nieprawidłowy email lub hasło."), "text/html");
        }

        if (!user.IsActive)
        {
            await _auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: model.Email,
                actorId: user.Id,
                resourceType: "Auth",
                success: false,
                failureReason: "Account inactive",
                ipAddress: clientIp,
                userAgent: Ua());

            _logger.LogWarning("Login attempt for inactive user: {Email}", model.Email);
            return Content(LoginPage(returnUrl,
                "Konto jest nieaktywne. Skontaktuj się z administratorem."), "text/html");
        }

        _rateLimiter.ClearFailures("login", clientIp);

        await _signInManager.SignInAsync(user, model.RememberMe);

        await _auditService.LogAsync(
            action: AuditAction.Login,
            actorEmail: model.Email,
            actorId: user.Id,
            resourceType: "Auth",
            ipAddress: clientIp,
            userAgent: Ua());

        _logger.LogInformation("User {UserId} logged in from {IP}", user.Id, clientIp);

        var decodedReturnUrl = !string.IsNullOrEmpty(returnUrl)
            ? Uri.UnescapeDataString(returnUrl)
            : null;

        var redirectUrl = !string.IsNullOrEmpty(decodedReturnUrl) && decodedReturnUrl.StartsWith("/")
            ? decodedReturnUrl
            : "/api/oauth/authorize";

        return Redirect(redirectUrl);
    }

    #endregion

    #region AUTHORIZATION ENDPOINT (RFC 6749 § 3.1)

    [HttpGet("authorize")]
    [AllowAnonymous]
    public async Task<IActionResult> Authorize(
        [FromQuery(Name = "response_type")]         string? responseType        = null,
        [FromQuery(Name = "client_id")]             string? clientId            = null,
        [FromQuery(Name = "redirect_uri")]          string? redirectUri         = null,
        [FromQuery(Name = "scope")]                 string? scope               = null,
        [FromQuery(Name = "state")]                 string? state               = null,
        [FromQuery(Name = "code_challenge")]        string? codeChallenge       = null,
        [FromQuery(Name = "code_challenge_method")] string? codeChallengeMethod = null,
        [FromQuery(Name = "nonce")]                 string? nonce               = null)
    {
        if (!User.Identity?.IsAuthenticated ?? true)
        {
            var returnUrl = Request.Path + Request.QueryString;
            return Redirect($"/api/oauth/account/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        try
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                              ?? User.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(userIdClaim))
            {
                _logger.LogWarning("Authorization attempt with invalid user claims");
                return BadRequest(new { error = "invalid_request", error_description = "User authentication is invalid" });
            }

            var userId = Guid.Parse(userIdClaim);

            // ── GlobalSession validation ──────────────────────────────────────
            // If the user carries a `sid` claim from their browser session, verify
            // the GlobalSession is still active. If it has been revoked (e.g. by
            // another app calling POST /api/oauth/logout), force re-authentication.
            var sid = User.FindFirstValue("sid");
            if (!string.IsNullOrEmpty(sid))
            {
                var globalSession = await _federation.GetActiveGlobalSessionAsync(sid);
                if (globalSession == null)
                {
                    _logger.LogWarning(
                        "GlobalSession revoked or expired for user {UserId} — forcing re-authentication", userId);
                    await _signInManager.SignOutAsync();
                    var returnUrl = Request.Path + Request.QueryString;
                    return Redirect($"/api/oauth/account/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
                }
            }

            if (string.IsNullOrWhiteSpace(responseType) || responseType != "code")
                return BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' response_type is supported" });

            if (string.IsNullOrWhiteSpace(clientId))
                return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });

            if (string.IsNullOrWhiteSpace(redirectUri))
                return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });

            if (string.IsNullOrWhiteSpace(state))
            {
                _logger.LogWarning("Authorization request without state parameter from client: {ClientId}", clientId);
                return BadRequest(new { error = "invalid_request", error_description = "state parameter is required for CSRF protection" });
            }

            var client = await _oauthService.GetClientByClientIdAsync(clientId);
            if (client == null || !client.IsActive)
            {
                _logger.LogWarning("Authorization attempt with invalid client: {ClientId}", clientId);
                return BadRequest(new { error = "invalid_client", error_description = "Client not found or inactive" });
            }

            if (!await _oauthService.ValidateRedirectUriAsync(client.Id, redirectUri))
            {
                _logger.LogWarning("Invalid redirect_uri={RedirectUri} for client={ClientId}", redirectUri, clientId);
                return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is not registered for this client" });
            }

            var requiresPkce = client.RequirePkce || client.ClientType != ClientType.Confidential;

            if (requiresPkce && string.IsNullOrWhiteSpace(codeChallenge))
            {
                _logger.LogWarning("PKCE required but code_challenge missing for client: {ClientId}", clientId);
                return RedirectToError(redirectUri, "invalid_request", "code_challenge is required for this client type", state);
            }

            if (!string.IsNullOrWhiteSpace(codeChallenge) && codeChallengeMethod != "S256")
                return RedirectToError(redirectUri, "invalid_request", "Only S256 code_challenge_method is supported", state);

            scope ??= "openid profile";

            if (scope.Contains("openid") && string.IsNullOrWhiteSpace(nonce))
            {
                _logger.LogWarning("OpenID Connect request without nonce from client: {ClientId}", clientId);
                return RedirectToError(redirectUri, "invalid_request", "nonce is required when using openid scope", state);
            }

            // ── Consent check ─────────────────────────────────────────────────
            // First-party clients always bypass consent (they are owned by this service).
            // Third-party clients check consent version + granted scopes; show screen if stale.
            if (client.RequireConsent && !client.FirstParty)
            {
                var alreadyConsented = await _oauthService.HasUserConsentedAsync(userId, client.Id, scope);
                if (!alreadyConsented)
                    return ShowConsentScreen(client, redirectUri, scope, state, codeChallenge, codeChallengeMethod, nonce);
            }

            var authCode = await _oauthService.CreateAuthorizationCodeAsync(
                userId, client.Id, redirectUri, scope, codeChallenge, codeChallengeMethod, nonce);

            _logger.LogInformation("Authorization code issued for UserId={UserId}, ClientId={ClientId}", userId, clientId);

            return Redirect(BuildRedirectUri(redirectUri, authCode.Code, state));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Authorization endpoint error");
            return StatusCode(500, new { error = "server_error", error_description = "An internal error occurred. Please try again." });
        }
    }

    [HttpPost("authorize/consent")]
    public async Task<IActionResult> GrantConsent()
    {
        try
        {
            var form = await Request.ReadFormAsync();

            if (!form.ContainsKey("clientId") || string.IsNullOrEmpty(form["clientId"].ToString()))
                return BadRequest(new { error = "invalid_request", error_description = "clientId is required" });

            if (!form.ContainsKey("redirectUri") || string.IsNullOrEmpty(form["redirectUri"].ToString()))
                return BadRequest(new { error = "invalid_request", error_description = "redirectUri is required" });

            var approved            = form.ContainsKey("approved") && form["approved"] == "true";
            var redirectUri         = form["redirectUri"].ToString();
            var state               = form["state"].ToString();
            var scope               = form["scope"].ToString();
            var clientId            = form["clientId"].ToString();
            var codeChallenge       = form["codeChallenge"].ToString();
            var codeChallengeMethod = form["codeChallengeMethod"].ToString();
            var nonce               = form["nonce"].ToString();

            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                              ?? User.FindFirst("sub")?.Value;

            if (string.IsNullOrEmpty(userIdClaim))
                return BadRequest(new { error = "invalid_request" });

            var userId    = Guid.Parse(userIdClaim);
            var userEmail = User.FindFirst(ClaimTypes.Email)?.Value ?? "unknown";

            var client = await _oauthService.GetClientByClientIdAsync(clientId);
            if (client == null)
            {
                _logger.LogWarning("Consent attempt for non-existent client: {ClientId}", clientId);
                return BadRequest(new { error = "invalid_client" });
            }

            if (!await _oauthService.ValidateRedirectUriAsync(client.Id, redirectUri))
            {
                _logger.LogWarning("Invalid redirect_uri in consent: {RedirectUri} for client: {ClientId}", redirectUri, clientId);
                return BadRequest(new { error = "invalid_request", error_description = "redirect_uri is not registered for this client" });
            }

            if (!approved)
            {
                await _auditService.LogAsync(
                    action: AuditAction.ConsentDenied,
                    actorEmail: userEmail,
                    actorId: userId,
                    resourceType: "OAuth",
                    resourceId: clientId,
                    resourceName: client.Name,
                    ipAddress: Ip(),
                    userAgent: Ua());

                _logger.LogInformation("User {UserId} denied consent for client {ClientId}", userId, clientId);
                return RedirectToError(redirectUri, "access_denied", "User denied authorization", state);
            }

            await _oauthService.GrantConsentAsync(userId, client.Id, scope);

            var authCode = await _oauthService.CreateAuthorizationCodeAsync(
                userId, client.Id, redirectUri, scope, codeChallenge, codeChallengeMethod, nonce);

            await _auditService.LogAsync(
                action: AuditAction.ConsentGranted,
                actorEmail: userEmail,
                actorId: userId,
                resourceType: "OAuth",
                resourceId: clientId,
                resourceName: client.Name,
                metadata: JsonSerializer.Serialize(new { scope }),  // ← poprawka
                ipAddress: Ip(),
                userAgent: Ua());

            _logger.LogInformation("Consent granted for UserId={UserId}, ClientId={ClientId}", userId, clientId);
            return Redirect(BuildRedirectUri(redirectUri, authCode.Code, state));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Consent endpoint error");
            return StatusCode(500, new { error = "server_error", error_description = "An internal error occurred during consent processing" });
        }
    }

    #endregion

    #region TOKEN ENDPOINT (RFC 6749 § 3.2)

    /// <summary>Exchange authorization code or refresh token for access/ID tokens.</summary>
    /// <remarks>
    /// Supports grant types: <c>authorization_code</c>, <c>refresh_token</c>, <c>client_credentials</c>.
    /// Confidential clients must authenticate via <c>client_secret</c> (legacy BCrypt hash or versioned <c>spc_</c> format).
    /// </remarks>
    [HttpPost("token")]
    [AllowAnonymous]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status429TooManyRequests)]
    public async Task<ActionResult<TokenResponse>> Token(
        [FromForm(Name = "grant_type")]    string  grantType,
        [FromForm(Name = "code")]          string? code         = null,
        [FromForm(Name = "refresh_token")] string? refreshToken = null,
        [FromForm(Name = "client_id")]     string? clientId     = "",
        [FromForm(Name = "client_secret")] string? clientSecret = null,
        [FromForm(Name = "code_verifier")] string? codeVerifier = null,
        [FromForm(Name = "redirect_uri")]  string? redirectUri  = null)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            if (string.IsNullOrWhiteSpace(clientId))
                return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });

            if (_rateLimiter.IsBlocked("client_auth", clientId))
            {
                _logger.LogWarning("Client authentication rate limit exceeded: {ClientId}", clientId);
                return StatusCode(429, new { error = "too_many_requests", error_description = "Too many failed authentication attempts. Please try again later." });
            }

            var client = await _oauthService.GetClientByClientIdAsync(clientId);
            if (client == null)
            {
                _logger.LogWarning("Token request for non-existent client: {ClientId}", clientId);
                return BadRequest(new { error = "invalid_client" });
            }

            if (client.ClientType == ClientType.Confidential)
            {
                try
                {
                    await _oauthService.ValidateClientCredentialsAsync(clientId, clientSecret);
                    _rateLimiter.ClearFailures("client_auth", clientId);
                }
                catch (OAuthException)
                {
                    _rateLimiter.RecordFailure("client_auth", clientId);

                    await _auditService.LogAsync(
                        action: AuditAction.LoginFailed,
                        actorEmail: clientId,
                        resourceType: "OAuth",
                        resourceId: clientId,
                        success: false,
                        failureReason: "Invalid client secret",
                        ipAddress: Ip(),
                        userAgent: Ua());

                    _logger.LogWarning("Failed client authentication: {ClientId}", clientId);
                    return BadRequest(new { error = "invalid_client" });
                }
            }

            if (grantType == "authorization_code")
            {
                if (string.IsNullOrEmpty(code))
                    return BadRequest(new { error = "invalid_request", error_description = "code is required" });

                var tokens = await _oauthService.ExchangeAuthorizationCodeAsync(
                    code, client.Id, redirectUri ?? "", codeVerifier);

                await _auditService.LogAsync(
                    action: AuditAction.TokenIssued,
                    actorEmail: clientId,
                    resourceType: "OAuth",
                    resourceId: clientId,
                    resourceName: client.Name,
                    metadata: """{"grant_type":"authorization_code"}""",  // ← poprawka
                    ipAddress: Ip(),
                    userAgent: Ua());

                _logger.LogInformation("Tokens issued via authorization_code for ClientId={ClientId}", clientId);
                _metrics.TokensIssued.WithLabels("authorization_code", clientId ?? "").Inc();
                _metrics.TokenEndpointDuration.WithLabels("authorization_code", "200").Observe(sw.ElapsedMilliseconds);
                return Ok(tokens);
            }

            if (grantType == "refresh_token")
            {
                if (string.IsNullOrEmpty(refreshToken))
                    return BadRequest(new { error = "invalid_request", error_description = "refresh_token is required" });

                var tokens = await _oauthService.RefreshTokenAsync(refreshToken, client.Id);

                await _auditService.LogAsync(
                    action: AuditAction.TokenRefreshed,
                    actorEmail: clientId,
                    resourceType: "OAuth",
                    resourceId: clientId,
                    resourceName: client.Name,
                    metadata: """{"grant_type":"refresh_token"}""",
                    ipAddress: Ip(),
                    userAgent: Ua());

                _logger.LogInformation("Tokens refreshed for ClientId={ClientId}", clientId);
                _metrics.TokensIssued.WithLabels("refresh_token", clientId ?? "").Inc();
                _metrics.TokenEndpointDuration.WithLabels("refresh_token", "200").Observe(sw.ElapsedMilliseconds);
                return Ok(tokens);
            }

            return BadRequest(new { error = "unsupported_grant_type", error_description = $"Grant type '{grantType}' is not supported" });
        }
        catch (RefreshTokenReuseDetectedException ex)
        {
            _logger.LogWarning("Refresh token reuse attack on client {ClientId}, user {UserId}", clientId, ex.UserId);
            _metrics.RefreshTokenReuseAttacks.Inc();
            _metrics.TokenEndpointFailures.WithLabels("reuse_attack", "refresh_token").Inc();
            return BadRequest(new { error = "invalid_grant", error_description = "Token reuse detected. All sessions have been revoked." });
        }
        catch (AuthorizationCodeReplayException ex)
        {
            _logger.LogWarning("Authorization code replay attempt on client {ClientId} (code prefix: {Prefix})", clientId, ex.CodePrefix);
            _metrics.AuthCodeReplays.Inc();
            _metrics.TokenEndpointFailures.WithLabels("replay", "authorization_code").Inc();
            return BadRequest(new { error = "invalid_grant", error_description = "Authorization code already used or invalid." });
        }
        catch (PkceException ex)
        {
            _logger.LogWarning("PKCE validation failed on client {ClientId}: {Reason}", clientId, ex.Reason);
            _metrics.PkceFailures.Inc();
            _metrics.TokenEndpointFailures.WithLabels("pkce_failed", grantType).Inc();
            return BadRequest(new { error = "invalid_grant", error_description = "PKCE verification failed." });
        }
        catch (OAuthException ex)
        {
            _logger.LogWarning("OAuth error on token endpoint: {Error} — {Desc}", ex.Error, ex.ErrorDescription);
            _metrics.TokenEndpointFailures.WithLabels(ex.Error, grantType).Inc();
            return BadRequest(new { error = ex.Error, error_description = ex.ErrorDescription });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Token exchange failed");
            _metrics.TokenEndpointFailures.WithLabels("invalid_grant", grantType).Inc();
            return BadRequest(new { error = "invalid_grant", error_description = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token endpoint error");
            return StatusCode(500, new { error = "server_error", error_description = "An internal error occurred" });
        }
    }

    #endregion

    #region GLOBAL LOGOUT (OIDC Back-Channel Federation)

    /// <summary>
    /// POST /api/oauth/logout
    ///
    /// Server-to-server endpoint. Called by a registered app when a user initiates
    /// local logout so that SpiceAuth can propagate the revocation to all other apps
    /// that share the same global session.
    ///
    /// Body (JSON): { sid, client_id, client_secret }
    ///
    /// Returns 200 idempotently (already-revoked sessions are handled gracefully).
    /// </summary>
    [HttpPost("logout")]
    [AllowAnonymous]
    [Consumes("application/json")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GlobalLogout([FromBody] GlobalLogoutRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Sid))
            return BadRequest(new { error = "invalid_request", error_description = "sid is required" });

        if (string.IsNullOrWhiteSpace(request.ClientId))
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });

        if (_rateLimiter.IsBlocked("client_auth", request.ClientId))
        {
            _logger.LogWarning("Logout rate limit exceeded for client: {ClientId}", request.ClientId);
            return StatusCode(429, new { error = "too_many_requests" });
        }

        try
        {
            await _oauthService.ValidateClientCredentialsAsync(request.ClientId, request.ClientSecret);
        }
        catch
        {
            _rateLimiter.RecordFailure("client_auth", request.ClientId);
            _logger.LogWarning("Logout: invalid client credentials for {ClientId}", request.ClientId);
            return Unauthorized(new { error = "invalid_client" });
        }

        _rateLimiter.ClearFailures("client_auth", request.ClientId);

        try
        {
            // Revoke the GlobalSession and dispatch logout_tokens to all registered apps.
            // Fire-and-forget is intentional: caller should not wait on network I/O to all apps.
            _ = Task.Run(() => _federation.RevokeAndDispatchAsync(
                request.Sid, request.ClientId, request.ClientSecret ?? string.Empty));

            await _auditService.LogAsync(
                action: AuditAction.Logout,
                actorEmail: request.ClientId,
                resourceType: "OAuth",
                resourceId: request.ClientId,
                metadata: $"{{\"sid\":\"{request.Sid[..Math.Min(8, request.Sid.Length)]}…\"}}",
                ipAddress: Ip(),
                userAgent: Ua());

            _logger.LogInformation(
                "Global logout initiated by client {ClientId} for sid=…{Tail}",
                request.ClientId, request.Sid[^Math.Min(6, request.Sid.Length)..]);

            return Ok(new { ok = true });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Global logout error for client {ClientId}", request.ClientId);
            return StatusCode(500, new { error = "server_error" });
        }
    }

    #endregion

    #region PROTECTED ENDPOINT

    [HttpGet("test-protected")]
    public IActionResult TestProtected() => Ok(new
    {
        message = "🛡️ Protected endpoint accessed successfully",
        userId  = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value ?? "unknown",
        email   = User.FindFirst(ClaimTypes.Email)?.Value,
        claims  = User.Claims.Select(c => new { c.Type, c.Value }).ToArray()
    });
    
    [HttpGet("/oauth/userinfo")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<IActionResult> UserInfo()
    {
        var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier)
                          ?? User.FindFirstValue("sub");

        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            return Unauthorized(new { error = "invalid_token" });

        try
        {
            var userInfo = await _oauthService.GetUserInfoAsync(userId);

            // Attach sid from the user's most-recent active GlobalSession.
            // If no active session exists the user has globally logged out — honour it.
            var sessions = await _federation.GetUserSessionsAsync(userId);
            var activeSid = sessions.FirstOrDefault(s => s.IsActive)?.Sid;

            if (activeSid == null)
            {
                _logger.LogWarning("UserInfo: no active GlobalSession for user {UserId} — rejecting", userId);
                return Unauthorized(new { error = "invalid_token", error_description = "Session expired or revoked" });
            }

            // Merge sid into the response (anonymous type cannot be patched — project to dict)
            var raw = System.Text.Json.JsonSerializer.SerializeToElement(userInfo);
            var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(raw.GetRawText())!;
            dict["sid"] = activeSid;

            return Ok(dict);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "UserInfo request failed for {UserId}", userIdClaim);
            return Unauthorized(new { error = "invalid_token" });
        }
    }

    #endregion

    #region PRIVATE HELPERS

    private static string LoginPage(string? returnUrl, string errorMessage = "")
    {
        var errorHtml = string.IsNullOrEmpty(errorMessage)
            ? ""
            : $"<div class='error'>{HttpUtility.HtmlEncode(errorMessage)}</div>";

        return $@"<!DOCTYPE html>
<html>
<head>
    <title>SpiceAuth - Logowanie</title>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <meta http-equiv='Content-Security-Policy' content=""default-src 'self'; style-src 'unsafe-inline'; script-src 'none';"">
    <style>
        *{{margin:0;padding:0;box-sizing:border-box}}
        body{{font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}
        .login-container{{background:white;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.3);max-width:400px;width:100%;overflow:hidden}}
        .login-header{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:32px;text-align:center}}
        .login-form{{padding:32px}}
        .form-group{{margin-bottom:20px}}
        input[type='email'],input[type='password']{{width:100%;padding:14px;border:2px solid #e1e5e9;border-radius:8px;font-size:16px;transition:border-color .2s;box-sizing:border-box}}
        input[type='email']:focus,input[type='password']:focus{{outline:none;border-color:#667eea}}
        .checkbox-group{{display:flex;align-items:center;gap:8px;margin-bottom:24px}}
        button{{width:100%;padding:16px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:transform .2s}}
        button:hover{{transform:translateY(-1px)}}
        button:active{{transform:translateY(0)}}
        .error{{color:#dc3545;margin-top:12px;padding:12px;background:#f8d7da;border-radius:6px;border-left:4px solid #dc3545}}
    </style>
</head>
<body>
    <div class='login-container'>
        <div class='login-header'>
            <h1>🔐 SpiceAuth</h1>
            <p>Zaloguj się aby kontynuować</p>
        </div>
        <div class='login-form'>
            <form method='post' action='/api/oauth/account/login?returnUrl={Uri.EscapeDataString(returnUrl ?? "")}'>
                <div class='form-group'>
                    <input name='Email' type='email' placeholder='Email' required autofocus autocomplete='email'>
                </div>
                <div class='form-group'>
                    <input name='Password' type='password' placeholder='Hasło' required autocomplete='current-password'>
                </div>
                <div class='checkbox-group'>
                    <input type='checkbox' name='RememberMe' id='remember'>
                    <label for='remember'>Zapamiętaj mnie</label>
                </div>
                {errorHtml}
                <button type='submit'>Zaloguj się</button>
            </form>
        </div>
    </div>
</body></html>";
    }

    private static string BuildRedirectUri(string redirectUri, string code, string state)
    {
        var uriBuilder = new UriBuilder(redirectUri);
        var query      = HttpUtility.ParseQueryString(uriBuilder.Query);
        query["code"]  = code;
        if (!string.IsNullOrWhiteSpace(state))
            query["state"] = state;
        uriBuilder.Query = query.ToString();
        return uriBuilder.ToString();
    }

    private IActionResult RedirectToError(string redirectUri, string error,
        string? errorDescription = null, string? state = null)
    {
        var uriBuilder = new UriBuilder(redirectUri);
        var query      = HttpUtility.ParseQueryString(uriBuilder.Query);
        query["error"] = error;
        if (!string.IsNullOrWhiteSpace(errorDescription))
            query["error_description"] = errorDescription;
        if (!string.IsNullOrWhiteSpace(state))
            query["state"] = state;
        uriBuilder.Query = query.ToString();
        return Redirect(uriBuilder.ToString());
    }

    private IActionResult ShowConsentScreen(
        OAuthClient client,
        string redirectUri, string scope, string state,
        string? codeChallenge, string? codeChallengeMethod, string? nonce)
    {
        var frontendUrl = _configuration["App:FrontendUrl"] ?? "http://localhost:3002";
        var query       = HttpUtility.ParseQueryString(string.Empty);

        query["clientId"]            = client.ClientId;
        query["clientName"]          = client.Name;
        query["clientDescription"]   = client.Description ?? "";
        query["redirectUri"]         = redirectUri;
        query["scope"]               = scope;
        query["state"]               = state;
        query["codeChallenge"]       = codeChallenge ?? "";
        query["codeChallengeMethod"] = codeChallengeMethod ?? "";
        query["nonce"]               = nonce ?? "";

        return Redirect($"{frontendUrl}/consent?{query}");
    }

    #endregion
}

public record LoginModel
{
    public string Email      { get; set; } = string.Empty;
    public string Password   { get; set; } = string.Empty;
    public bool   RememberMe { get; set; } = false;
}

public record GlobalLogoutRequest
{
    public string  Sid          { get; init; } = string.Empty;
    public string  ClientId     { get; init; } = string.Empty;
    public string? ClientSecret { get; init; }
}
