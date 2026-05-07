using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Application.Services.Security;

namespace SpiceAuth.API.Controllers;

/// <summary>
/// Session registration API — called server-to-server by registered apps
/// immediately after a user completes the OAuth flow on their side.
/// Enables SpiceAuth to dispatch back-channel logout tokens when the
/// global session is revoked.
/// </summary>
[ApiController]
[Route("api/sessions")]
public sealed class SessionsController(
    IFederationService federation,
    IUriSanitizer uriSanitizer,
    ILogger<SessionsController> logger) : ControllerBase
{
    /// <summary>
    /// POST /api/sessions/register
    ///
    /// Body (JSON or form):
    ///   sid                  — SpiceAuth global session ID from the id_token
    ///   app                  — registered app name
    ///   localSessionId       — optional: the app's own session ID for this user
    ///   backchannelLogoutUri — URI SpiceAuth will POST logout_token to
    ///   client_id            — OAuth client_id
    ///   client_secret        — OAuth client_secret
    ///
    /// Returns 200 on success (idempotent — re-registering updates lastSeenAt).
    /// Returns 400/401 on validation failure.
    /// </summary>
    [HttpPost("register")]
    [ProducesResponseType(typeof(RegisterSessionResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Register([FromBody] RegisterSessionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Sid))
            return BadRequest(new { error = "invalid_request", error_description = "sid is required" });

        if (string.IsNullOrWhiteSpace(request.App))
            return BadRequest(new { error = "invalid_request", error_description = "app is required" });

        if (string.IsNullOrWhiteSpace(request.BackchannelLogoutUri))
            return BadRequest(new { error = "invalid_request", error_description = "backchannelLogoutUri is required" });

        if (string.IsNullOrWhiteSpace(request.ClientId))
            return BadRequest(new { error = "invalid_request", error_description = "client_id is required" });

        var uriCheck = await uriSanitizer.ValidateAsync(request.BackchannelLogoutUri);
        if (!uriCheck.IsValid)
            return BadRequest(new { error = "invalid_request", error_description = uriCheck.Error });

        try
        {
            await federation.RegisterAppSessionAsync(
                sid: request.Sid,
                appName: request.App,
                localSessionId: request.LocalSessionId,
                backchannelLogoutUri: request.BackchannelLogoutUri,
                clientId: request.ClientId,
                clientSecret: request.ClientSecret ?? string.Empty);

            logger.LogInformation(
                "Session registered: app={App}, sid=…{Tail}",
                request.App, request.Sid[^Math.Min(6, request.Sid.Length)..]);

            return Ok(new RegisterSessionResponse { Ok = true });
        }
        catch (UnauthorizedAccessException ex)
        {
            logger.LogWarning("Session registration unauthorized: {Message}", ex.Message);
            return Unauthorized(new { error = "unauthorized", error_description = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            logger.LogWarning("Session registration invalid: {Message}", ex.Message);
            return BadRequest(new { error = "invalid_session", error_description = ex.Message });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Session registration error for app={App}", request.App);
            return StatusCode(500, new { error = "server_error" });
        }
    }
}

public record RegisterSessionRequest
{
    public string  Sid                  { get; init; } = string.Empty;
    public string  App                  { get; init; } = string.Empty;
    public string? LocalSessionId       { get; init; }
    public string  BackchannelLogoutUri { get; init; } = string.Empty;
    public string  ClientId             { get; init; } = string.Empty;
    public string? ClientSecret         { get; init; }
}

public record RegisterSessionResponse
{
    public bool Ok { get; init; }
}
