using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.API.Controllers;

/// <summary>
/// Session visibility and management for the authenticated user.
/// GET  /api/account/sessions          — list all sessions (active + historical)
/// DELETE /api/account/sessions/{id}   — revoke a specific session
/// </summary>
[ApiController]
[Route("api/account/sessions")]
[Authorize]
public sealed class AccountSessionsController(
    IFederationService federation,
    IAuditService auditService,
    ILogger<AccountSessionsController> logger) : ControllerBase
{
    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    private string Ua() => HttpContext.Request.Headers.UserAgent.ToString();

    [HttpGet]
    public async Task<IActionResult> GetSessions()
    {
        var userId = GetUserId();
        if (userId == null) return Unauthorized();

        var sessions = await federation.GetUserSessionsAsync(userId.Value);

        var result = sessions.Select(s => new
        {
            s.Id,
            s.Sid,
            s.CreatedAt,
            s.ExpiresAt,
            s.LastActivityAt,
            s.IpAddress,
            s.UserAgent,
            s.Location,
            s.DeviceFingerprint,
            IsActive   = s.IsActive,
            RevokedAt  = s.RevokedAt,
            AppCount   = s.AppSessions.Count
        });

        return Ok(result);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> RevokeSession(Guid id)
    {
        var userId = GetUserId();
        if (userId == null) return Unauthorized();

        var sessions = await federation.GetUserSessionsAsync(userId.Value);
        var target   = sessions.FirstOrDefault(s => s.Id == id);

        if (target == null)
            return NotFound(new { error = "session_not_found" });

        if (!target.IsActive)
            return Ok(new { ok = true, note = "already_revoked" });

        await federation.RevokeGlobalSessionAsync(target.Sid);

        _ = Task.Run(() =>
            federation.RevokeAndDispatchAsync(target.Sid, clientId: string.Empty, clientSecret: string.Empty)
                .ContinueWith(t =>
                {
                    if (t.Exception != null)
                        logger.LogError(t.Exception, "Backchannel dispatch error revoking session {Id}", id);
                }, TaskScheduler.Default));

        await auditService.LogAsync(
            action: AuditAction.GlobalSessionRevoked,
            actorEmail: User.FindFirstValue(ClaimTypes.Email) ?? "unknown",
            actorId: userId,
            resourceType: "Session",
            resourceId: id.ToString(),
            metadata: $"{{\"sid\":\"{target.Sid[..Math.Min(8, target.Sid.Length)]}…\"}}",
            ipAddress: Ip(),
            userAgent: Ua());

        logger.LogInformation("User {UserId} revoked session {Id}", userId, id);
        return Ok(new { ok = true });
    }

    private Guid? GetUserId()
    {
        var claim = User.FindFirstValue(ClaimTypes.NameIdentifier)
                 ?? User.FindFirstValue("sub");
        return Guid.TryParse(claim, out var id) ? id : null;
    }
}
