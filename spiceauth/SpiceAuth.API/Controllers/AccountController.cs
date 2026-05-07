using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Web;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.API.Controllers;

[Route("oauth/account")]
[AllowAnonymous]
public class AccountController(
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager,
    IFederationService federation,
    IAuditService auditService,
    ILogger<AccountController> logger) : Controller
{
    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    private string Ua() => HttpContext.Request.Headers.UserAgent.ToString();

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(returnUrl) && !Url.IsLocalUrl(returnUrl))
        {
            logger.LogWarning("Invalid returnUrl rejected: {ReturnUrl}", returnUrl);
            returnUrl = null;
        }

        return Content(RenderLoginPage(returnUrl), "text/html");
    }

    [HttpPost("login")]
    public async Task<IActionResult> LoginPost(
        [FromForm] string email,
        [FromForm] string password,
        [FromForm] bool rememberMe = false,
        [FromQuery] string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(returnUrl) && !Url.IsLocalUrl(returnUrl))
        {
            logger.LogWarning("Invalid returnUrl rejected: {ReturnUrl}", returnUrl);
            returnUrl = null;
        }

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return Content(RenderLoginPage(returnUrl, "Email i hasło są wymagane."), "text/html");

        var user = await userManager.FindByEmailAsync(email);

        if (user == null || !await userManager.CheckPasswordAsync(user, password))
        {
            await auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: email,
                resourceType: "Auth",
                success: false,
                failureReason: "Invalid credentials",
                ipAddress: Ip(),
                userAgent: Ua());

            logger.LogWarning("Failed login for {Email} from {IP}", email, Ip());
            return Content(RenderLoginPage(returnUrl, "Nieprawidłowy email lub hasło."), "text/html");
        }

        if (!user.IsActive)
        {
            await auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: email,
                actorId: user.Id,
                resourceType: "Auth",
                success: false,
                failureReason: "Account inactive",
                ipAddress: Ip(),
                userAgent: Ua());

            logger.LogWarning("Login attempt for inactive user: {Email}", email);
            return Content(RenderLoginPage(returnUrl, "Konto jest nieaktywne. Skontaktuj się z administratorem."), "text/html");
        }

        // CheckPasswordSignInAsync validates credentials + handles lockout without committing a cookie.
        var checkResult = await signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);

        if (checkResult.IsLockedOut)
        {
            await auditService.LogAsync(
                action: AuditAction.LoginFailed,
                actorEmail: email,
                actorId: user.Id,
                resourceType: "Auth",
                success: false,
                failureReason: "Account locked out",
                ipAddress: Ip(),
                userAgent: Ua());

            logger.LogWarning("Account locked out: {Email}", email);
            return Content(RenderLoginPage(returnUrl, "Konto zablokowane. Zbyt wiele prób logowania."), "text/html");
        }

        if (!checkResult.Succeeded)
            return Content(RenderLoginPage(returnUrl, "Nieprawidłowy email lub hasło."), "text/html");

        // Create a GlobalSession — this is the federation anchor for this browser session.
        var globalSession = await federation.CreateGlobalSessionAsync(
            user.Id, Ip(), Ua());

        // Sign in with the sid claim embedded so every downstream request can resolve the GlobalSession.
        var authProps = new AuthenticationProperties { IsPersistent = rememberMe };
        var extraClaims = new[] { new Claim("sid", globalSession.Sid) };
        await signInManager.SignInWithClaimsAsync(user, authProps, extraClaims);

        await auditService.LogAsync(
            action: AuditAction.Login,
            actorEmail: email,
            actorId: user.Id,
            resourceType: "Auth",
            metadata: $"{{\"sid\":\"{globalSession.Sid[..Math.Min(8, globalSession.Sid.Length)]}…\"}}",
            ipAddress: Ip(),
            userAgent: Ua());

        logger.LogInformation("User {Email} logged in from {IP} (GlobalSession created)", email, Ip());

        var redirectUrl = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl)
            ? returnUrl
            : "/oauth/authorize";

        return Redirect(redirectUrl);
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var email  = User.FindFirstValue(ClaimTypes.Email) ?? "unknown";
        var userId = Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : (Guid?)null;
        var sid    = User.FindFirstValue("sid");

        // Revoke the GlobalSession first (marks revokedAt in DB so any concurrent
        // authorize request for the same session is forced to re-authenticate).
        if (!string.IsNullOrEmpty(sid))
        {
            await federation.RevokeGlobalSessionAsync(sid);

            // Dispatch backchannel logout tokens to all registered apps.
            // Fire-and-forget: network I/O to external apps must not block the user's redirect.
            _ = Task.Run(() =>
                federation.RevokeAndDispatchAsync(sid, clientId: string.Empty, clientSecret: string.Empty)
                    .ContinueWith(t =>
                    {
                        if (t.Exception != null)
                            logger.LogError(t.Exception, "Backchannel dispatch error on logout");
                    }, TaskScheduler.Default));
        }

        await signInManager.SignOutAsync();

        await auditService.LogAsync(
            action: AuditAction.Logout,
            actorEmail: email,
            actorId: userId,
            resourceType: "Auth",
            ipAddress: Ip(),
            userAgent: Ua());

        logger.LogInformation("User {Email} logged out", email);
        return Redirect("/");
    }

    private static string RenderLoginPage(string? returnUrl, string errorMessage = "")
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
        .box{{background:white;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.3);max-width:400px;width:100%;overflow:hidden}}
        .header{{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:32px;text-align:center}}
        .body{{padding:32px}}
        .field{{margin-bottom:20px}}
        input[type=email],input[type=password]{{width:100%;padding:14px;border:2px solid #e1e5e9;border-radius:8px;font-size:16px;transition:border-color .2s}}
        input[type=email]:focus,input[type=password]:focus{{outline:none;border-color:#667eea}}
        .remember{{display:flex;align-items:center;gap:8px;margin-bottom:24px}}
        button{{width:100%;padding:16px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}}
        .error{{color:#dc3545;padding:12px;background:#f8d7da;border-radius:6px;border-left:4px solid #dc3545;margin-bottom:16px}}
    </style>
</head>
<body>
    <div class='box'>
        <div class='header'>
            <h1>🔐 SpiceAuth</h1>
            <p>Zaloguj się aby kontynuować</p>
        </div>
        <div class='body'>
            {errorHtml}
            <form method='post' action='/oauth/account/login?returnUrl={Uri.EscapeDataString(returnUrl ?? "")}'>
                <div class='field'>
                    <input name='email' type='email' placeholder='Email' required autofocus autocomplete='email'>
                </div>
                <div class='field'>
                    <input name='password' type='password' placeholder='Hasło' required autocomplete='current-password'>
                </div>
                <div class='remember'>
                    <input type='checkbox' name='rememberMe' id='rem'>
                    <label for='rem'>Zapamiętaj mnie</label>
                </div>
                <button type='submit'>Zaloguj się</button>
            </form>
        </div>
    </div>
</body></html>";
    }
}
