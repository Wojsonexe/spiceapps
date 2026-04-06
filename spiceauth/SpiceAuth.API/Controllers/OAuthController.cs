using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Json;
using System.Web;
using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("/api/[controller]")]
[Authorize(AuthenticationSchemes = "Identity.Application")]
public sealed class OAuthController : ControllerBase
{
    private readonly IOAuthService _oauthService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IAuditService _auditService;
    private readonly ILogger<OAuthController> _logger;
    private readonly IConfiguration _configuration;

    private static readonly ConcurrentDictionary<string, (int Attempts, DateTime LockUntil)>
        FailedClientAuth = new();

    private static readonly ConcurrentDictionary<string, (int Attempts, DateTime LockUntil)>
        FailedLoginAttempts = new();

    public OAuthController(
        IOAuthService oauthService,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IAuditService auditService,
        ILogger<OAuthController> logger,
        IConfiguration configuration)
    {
        _oauthService  = oauthService;
        _userManager   = userManager;
        _signInManager = signInManager;
        _auditService  = auditService;
        _logger        = logger;
        _configuration = configuration;
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

        if (FailedLoginAttempts.TryGetValue(clientIp, out var lockInfo) &&
            lockInfo.LockUntil > DateTime.UtcNow)
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
            FailedLoginAttempts.AddOrUpdate(clientIp,
                (1, DateTime.UtcNow),
                (_, old) => (old.Attempts + 1,
                    old.Attempts >= 4 ? DateTime.UtcNow.AddMinutes(15) : old.LockUntil));

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

        FailedLoginAttempts.TryRemove(clientIp, out _);

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

            if (client.RequireConsent)
                return ShowConsentScreen(client, redirectUri, scope, state, codeChallenge, codeChallengeMethod, nonce);

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

    [HttpPost("token")]
    [AllowAnonymous]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    public async Task<ActionResult<TokenResponse>> Token(
        [FromForm(Name = "grant_type")]    string  grantType,
        [FromForm(Name = "code")]          string? code         = null,
        [FromForm(Name = "refresh_token")] string? refreshToken = null,
        [FromForm(Name = "client_id")]     string? clientId     = "",
        [FromForm(Name = "client_secret")] string? clientSecret = null,
        [FromForm(Name = "code_verifier")] string? codeVerifier = null,
        [FromForm(Name = "redirect_uri")]  string? redirectUri  = null)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(clientId))
                return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });

            if (FailedClientAuth.TryGetValue(clientId, out var lockInfo) &&
                lockInfo.LockUntil > DateTime.UtcNow)
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
                if (string.IsNullOrEmpty(clientSecret))
                    return BadRequest(new { error = "invalid_client", error_description = "client_secret is required for confidential clients" });

                if (!BCrypt.Net.BCrypt.Verify(clientSecret, client.ClientSecretHash))
                {
                    FailedClientAuth.AddOrUpdate(clientId,
                        (1, DateTime.UtcNow),
                        (_, old) => (old.Attempts + 1,
                            old.Attempts >= 4 ? DateTime.UtcNow.AddMinutes(15) : old.LockUntil));

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

                FailedClientAuth.TryRemove(clientId, out _);
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
                    metadata: """{"grant_type":"refresh_token"}""",       // ← poprawka
                    ipAddress: Ip(),
                    userAgent: Ua());

                _logger.LogInformation("Tokens refreshed for ClientId={ClientId}", clientId);
                return Ok(tokens);
            }

            return BadRequest(new { error = "unsupported_grant_type", error_description = $"Grant type '{grantType}' is not supported" });
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogWarning(ex, "Token exchange failed");
            return BadRequest(new { error = "invalid_grant", error_description = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token endpoint error");
            return StatusCode(500, new { error = "server_error", error_description = "An internal error occurred" });
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
            return Ok(userInfo);
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

    public static (int ClientsRemoved, int LoginsRemoved) CleanupExpiredLocks()
    {
        var now = DateTime.UtcNow;

        var expiredClients = FailedClientAuth
            .Where(x => x.Value.LockUntil < now.AddHours(-1))
            .Select(x => x.Key).ToList();
        foreach (var key in expiredClients)
            FailedClientAuth.TryRemove(key, out _);

        var expiredLogins = FailedLoginAttempts
            .Where(x => x.Value.LockUntil < now.AddHours(-1))
            .Select(x => x.Key).ToList();
        foreach (var key in expiredLogins)
            FailedLoginAttempts.TryRemove(key, out _);

        return (expiredClients.Count, expiredLogins.Count);
    }

    #endregion
}

public record LoginModel
{
    public string Email      { get; set; } = string.Empty;
    public string Password   { get; set; } = string.Empty;
    public bool   RememberMe { get; set; } = false;
}
