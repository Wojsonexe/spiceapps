using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
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
    IConfiguration configuration,
    ILogger<AccountController> logger) : Controller
{
    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    private string Ua() => HttpContext.Request.Headers.UserAgent.ToString();

    private IActionResult RedirectToLoginPage(string? returnUrl, string? error = null)
    {
        var frontendUrl = configuration["App:FrontendUrl"] ?? "http://localhost:3002";
        var url = string.IsNullOrEmpty(returnUrl)
            ? $"{frontendUrl}/login"
            : $"{frontendUrl}/login?returnUrl={Uri.EscapeDataString(returnUrl)}";
        if (!string.IsNullOrEmpty(error))
            url += (url.Contains('?') ? "&" : "?") + $"error={Uri.EscapeDataString(error)}";
        return Redirect(url);
    }

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(returnUrl) && !Url.IsLocalUrl(returnUrl))
        {
            logger.LogWarning("Invalid returnUrl rejected: {ReturnUrl}", returnUrl);
            returnUrl = null;
        }

        return RedirectToLoginPage(returnUrl);
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
            return RedirectToLoginPage(returnUrl, "Email i hasło są wymagane.");

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
            return RedirectToLoginPage(returnUrl, "Nieprawidłowy email lub hasło.");
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
            return RedirectToLoginPage(returnUrl, "Konto jest nieaktywne. Skontaktuj się z administratorem.");
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
            return RedirectToLoginPage(returnUrl, "Konto zablokowane. Zbyt wiele prób logowania.");
        }

        if (!checkResult.Succeeded)
            return RedirectToLoginPage(returnUrl, "Nieprawidłowy email lub hasło.");

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
            : "/api/oauth/authorize";

        return Redirect(redirectUrl);
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await PerformLogout();
        return Redirect("/");
    }

    /// <summary>
    /// OIDC RP-Initiated Logout (GET).
    /// Kaczucha redirects here after clearing its own session.
    /// Clears the SpiceAuth browser cookie and sends the user to redirect_uri.
    /// </summary>
    [HttpGet("logout")]
    [AllowAnonymous]
    public async Task<IActionResult> LogoutGet([FromQuery] string? redirect_uri = null)
    {
        if (User.Identity?.IsAuthenticated == true)
            await PerformLogout();

        // Only allow absolute URIs — prevents open redirect to relative paths that
        // could be confused with local paths on a different host.
        var safe = !string.IsNullOrEmpty(redirect_uri)
            && Uri.TryCreate(redirect_uri, UriKind.Absolute, out _);

        return Redirect(safe ? redirect_uri! : "/");
    }

    private async Task PerformLogout()
    {
        var email  = User.FindFirstValue(ClaimTypes.Email) ?? "unknown";
        var userId = Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : (Guid?)null;
        var sid    = User.FindFirstValue("sid");

        if (!string.IsNullOrEmpty(sid))
        {
            await federation.RevokeGlobalSessionAsync(sid);

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
    }
}
