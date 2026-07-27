// SpiceAuth/API/Controllers/ExternalAuthController.cs

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.Services.Identity;

namespace SpiceAuth.API.Controllers;

[Route("api/oauth/external")]
[ApiController]
public class ExternalAuthController(
    IExternalAuthService externalAuthService,
    IConfiguration configuration,
    ILogger<ExternalAuthController> logger) : ControllerBase
{
    [HttpGet("discord/login")]
    [AllowAnonymous]
    public IActionResult LoginWithDiscord([FromQuery] string? returnUrl = null)
    {
        var redirectUri = Url.Action(nameof(DiscordCallback), null,
            new { returnUrl }, Request.Scheme)!;

        var props = new AuthenticationProperties
        {
            RedirectUri = redirectUri,
            Items       = { { "scheme", "Discord" } }
        };

        // If the browser has a valid SpiceHub accessToken cookie, treat this as a
        // link request so clicking "Connect Discord" doesn't switch the active account.
        var cookieToken = Request.Cookies["accessToken"];
        if (!string.IsNullOrEmpty(cookieToken))
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(cookieToken);
                if (jwt.ValidTo > DateTime.UtcNow)
                {
                    var sub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
                    if (!string.IsNullOrEmpty(sub))
                        props.Items["link_userId"] = sub;
                }
            }
            catch { /* malformed cookie — proceed as anonymous login */ }
        }

        return Challenge(props, "Discord");
    }

    [HttpGet("discord/link")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public IActionResult LinkDiscord()
    {
        var userId = User.FindFirstValue("sub")
            ?? User.FindFirstValue(ClaimTypes.NameIdentifier);

        var redirectUri = Url.Action(nameof(DiscordCallback), null,
            new { link = true }, Request.Scheme)!;

        var props = new AuthenticationProperties
        {
            RedirectUri = redirectUri,
            Items       =
            {
                { "scheme",      "Discord" },
                { "link",        "true"    },
                { "link_userId", userId!   }
            }
        };

        return Challenge(props, "Discord");
    }

    // ── CALLBACK Discord ──────────────────────────────────────────────────────
    // Route intentionally differs from CallbackPath (/discord/callback) to prevent
    // the OAuth middleware from intercepting the post-redirect request.
    [HttpGet("discord/complete")]
    [AllowAnonymous]
    public async Task<IActionResult> DiscordCallback(
        [FromQuery] bool link = false,
        [FromQuery] string? returnUrl = null)
    {
        var result = await HttpContext.AuthenticateAsync("Identity.External");
        await HttpContext.SignOutAsync("Identity.External");

        if (!result.Succeeded || result.Principal == null)
        {
            logger.LogWarning("Discord authentication failed: {Error}",
                result.Failure?.Message ?? "unknown");
            return Redirect($"{configuration["App:FrontendUrl"]}/auth/error?reason=discord_failed");
        }

        var providerUserId = result.Principal.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var email          = result.Principal.FindFirstValue(ClaimTypes.Email);
        var username       = result.Principal.FindFirstValue("urn:discord:username")
                             ?? result.Principal.FindFirstValue(ClaimTypes.Name);
        var avatarUrl      = result.Principal.FindFirstValue("urn:discord:avatar");
        var emailVerified  = result.Principal.FindFirstValue("urn:discord:verified") == "true";

        // Link flow: either initiated via GET /discord/link (Bearer) or via /discord/login
        // when the browser carried a valid accessToken cookie (cookie-based detection).
        string? linkUserIdStr = null;
        result.Properties?.Items.TryGetValue("link_userId", out linkUserIdStr);

        if (link || !string.IsNullOrEmpty(linkUserIdStr))
        {
            if (!Guid.TryParse(linkUserIdStr, out var linkUserId))
                return BadRequest(new { error = "Nieprawidłowy userId do połączenia" });

            var linked = await externalAuthService.LinkExternalProviderAsync(
                linkUserId, "discord", providerUserId, username, email, avatarUrl);

            var status = linked ? "success" : "already_linked";
            return Redirect($"{configuration["App:FrontendUrl"]}/settings/connections?discord={status}");
        }

        // Detect case 3b: cookie session (Identity.Application) — user already logged in via browser
        Guid? authenticatedUserId = null;
        if (HttpContext.User.Identity?.IsAuthenticated == true)
        {
            var uidStr = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
                         ?? HttpContext.User.FindFirstValue("sub");
            if (Guid.TryParse(uidStr, out var uid))
                authenticatedUserId = uid;
        }

        var authResult = await externalAuthService.AuthenticateExternalAsync(
            "discord", providerUserId, email, username, avatarUrl, emailVerified, authenticatedUserId);

        var frontendUrl = configuration["App:FrontendUrl"];

        if (!authResult.Success)
        {
            if (authResult.ErrorCode == "email_conflict")
            {
                var hint = Uri.EscapeDataString(email ?? string.Empty);
                return Redirect($"{frontendUrl}/auth/link-required?hint={hint}");
            }

            logger.LogError("External auth failed: {Message}", authResult.Message);
            return Redirect($"{frontendUrl}/auth/error?reason=auth_failed");
        }

        if (authResult.WasLinked)
            return Redirect($"{frontendUrl}/settings/connections?discord=success");

        return Redirect(
            $"{frontendUrl}/auth/callback" +
            $"?access_token={Uri.EscapeDataString(authResult.AccessToken!)}" +
            $"&refresh_token={Uri.EscapeDataString(authResult.RefreshToken!)}");
    }

    [HttpDelete("discord/unlink")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<IActionResult> UnlinkDiscord()
    {
        var userId = Guid.Parse(User.FindFirstValue("sub")
            ?? User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var ok = await externalAuthService.UnlinkExternalProviderAsync(userId, "discord");

        return ok
            ? Ok(new { message = "Discord odłączony pomyślnie." })
            : BadRequest(new { error = "Nie można odłączyć — brak hasła lub to jedyna metoda logowania." });
    }

    [HttpGet("providers")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public async Task<IActionResult> GetLinkedProviders()
    {
        var userId = Guid.Parse(User.FindFirstValue("sub")
            ?? User.FindFirstValue(ClaimTypes.NameIdentifier)!);

        var providers = await externalAuthService.GetLinkedProvidersAsync(userId);
        return Ok(providers);
    }
}
