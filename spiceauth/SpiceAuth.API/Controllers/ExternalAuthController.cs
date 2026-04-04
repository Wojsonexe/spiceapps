// SpiceAuth/API/Controllers/ExternalAuthController.cs

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

    // ── CALLBACK Discord ──────────────────────────────────────
    [HttpGet("discord/callback")]
    [AllowAnonymous]
    public async Task<IActionResult> DiscordCallback(
        [FromQuery] bool link = false,
        [FromQuery] string? returnUrl = null)
    {
        var result = await HttpContext.AuthenticateAsync("Discord");

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

        if (link)
        {
            string? linkUserIdStr = null;
            result.Properties?.Items.TryGetValue("link_userId", out linkUserIdStr);

            if (!Guid.TryParse(linkUserIdStr, out var linkUserId))
                return BadRequest(new { error = "Nieprawidłowy userId do połączenia" });

            var linked = await externalAuthService.LinkExternalProviderAsync(
                linkUserId, "discord", providerUserId, username, email);

            var status = linked ? "success" : "already_linked";
            return Redirect($"{configuration["App:FrontendUrl"]}/settings/connections?discord={status}");
        }


        var authResult = await externalAuthService.AuthenticateExternalAsync(
            "discord", providerUserId, email, username, avatarUrl);

        if (!authResult.Success)
        {
            logger.LogError("External auth failed: {Message}", authResult.Message);
            return Redirect($"{configuration["App:FrontendUrl"]}/auth/error?reason=auth_failed");
        }

        var frontendUrl = configuration["App:FrontendUrl"];
        return Redirect(
            $"{frontendUrl}/auth/callback" +
            $"?access_token={authResult.AccessToken}" +
            $"&refresh_token={authResult.RefreshToken}");
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
