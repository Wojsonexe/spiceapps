using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.API.Controllers;

/// <summary>
/// GET /health/auth — structured auth-subsystem health check.
/// Intentionally separate from /health (DB-only) so load balancers can probe
/// auth-specific liveness without noise from unrelated infra.
/// </summary>
[ApiController]
[Route("health")]
[AllowAnonymous]
public sealed class HealthAuthController(
    DbContext dbContext,
    IKeyManagementService keyManagement,
    ILogger<HealthAuthController> logger) : ControllerBase
{
    [HttpGet("auth")]
    [Produces("application/json")]
    public async Task<IActionResult> GetAuthHealth(CancellationToken ct)
    {
        var checks = new Dictionary<string, object>();
        var healthy = true;

        // ── Database ─────────────────────────────────────────────────────────
        try
        {
            await dbContext.Database.ExecuteSqlRawAsync("SELECT 1", ct);
            checks["database"] = new { ok = true };
        }
        catch (Exception ex)
        {
            checks["database"] = new { ok = false, error = ex.Message };
            healthy = false;
            logger.LogError(ex, "HealthAuth: database check failed");
        }

        // ── Signing key ───────────────────────────────────────────────────────
        try
        {
            var key = await keyManagement.GetPrimaryKeyAsync();
            var expiresIn = key.ExpiresAt - DateTime.UtcNow;
            var keyOk     = expiresIn > TimeSpan.Zero;

            checks["signing_key"] = new
            {
                ok        = keyOk,
                kid       = key.KeyId,
                algorithm = key.Algorithm,
                expires_in_days = Math.Round(expiresIn.TotalDays, 1),
                is_primary = key.IsPrimary
            };

            if (!keyOk)
            {
                healthy = false;
                logger.LogError("HealthAuth: primary signing key {Kid} has EXPIRED", key.KeyId);
            }
            else if (expiresIn.TotalDays < 7)
            {
                logger.LogWarning("HealthAuth: signing key expires in {Days:F1} days", expiresIn.TotalDays);
            }
        }
        catch (Exception ex)
        {
            checks["signing_key"] = new { ok = false, error = ex.Message };
            healthy = false;
            logger.LogError(ex, "HealthAuth: signing key check failed");
        }

        // ── Clock drift ───────────────────────────────────────────────────────
        var driftSeconds = Math.Abs((DateTimeOffset.UtcNow - DateTimeOffset.Now).TotalSeconds);
        var clockOk      = driftSeconds < 30;
        checks["clock"] = new { ok = clockOk, drift_seconds = Math.Round(driftSeconds, 1) };
        if (!clockOk)
        {
            healthy = false;
            logger.LogWarning("HealthAuth: clock drift {Drift:F1}s exceeds 30s threshold", driftSeconds);
        }

        // ── Federation dispatch backlog ────────────────────────────────────────
        try
        {
            var pending = await dbContext.Set<FederationDispatch>()
                .CountAsync(d => d.Status == DispatchStatus.Pending ||
                                 d.Status == DispatchStatus.Failed, ct);

            var deadLetter = await dbContext.Set<FederationDispatch>()
                .CountAsync(d => d.Status == DispatchStatus.DeadLetter, ct);

            var backlogOk = pending < 100;
            checks["federation_dispatch"] = new
            {
                ok           = backlogOk,
                pending      = pending,
                dead_letter  = deadLetter
            };

            if (!backlogOk)
                logger.LogWarning("HealthAuth: federation dispatch backlog is {Count}", pending);
        }
        catch (Exception ex)
        {
            checks["federation_dispatch"] = new { ok = false, error = ex.Message };
            logger.LogError(ex, "HealthAuth: federation dispatch check failed");
        }

        var response = new
        {
            ok        = healthy,
            timestamp = DateTime.UtcNow.ToString("O"),
            checks
        };

        return healthy ? Ok(response) : StatusCode(503, response);
    }
}
