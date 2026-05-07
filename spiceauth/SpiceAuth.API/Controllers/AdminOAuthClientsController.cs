using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.API.Controllers;

/// <summary>
/// Admin-only OAuth client secret lifecycle management.
/// POST   /api/admin/oauth-clients/{clientId}/secrets          — generate new secret
/// DELETE /api/admin/oauth-clients/{clientId}/secrets/{id}     — revoke a secret
/// GET    /api/admin/oauth-clients/{clientId}/secrets          — list secrets (no hashes)
/// </summary>
[ApiController]
[Route("api/admin/oauth-clients")]
[Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
public sealed class AdminOAuthClientsController(
    DbContext dbContext,
    IAuditService auditService,
    ILogger<AdminOAuthClientsController> logger) : ControllerBase
{
    private (Guid? id, string email) Actor() => (
        Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null,
        User.FindFirstValue(ClaimTypes.Email) ?? "unknown");

    // ── GET /api/admin/oauth-clients/{clientId}/secrets ───────────────────────

    [HttpGet("{clientId:guid}/secrets")]
    public async Task<IActionResult> ListSecrets(Guid clientId)
    {
        var client = await dbContext.Set<OAuthClient>()
            .FirstOrDefaultAsync(c => c.Id == clientId);

        if (client is null) return NotFound(new { error = "client_not_found" });

        var secrets = await dbContext.Set<ClientSecret>()
            .Where(s => s.ClientInternalId == clientId)
            .OrderByDescending(s => s.CreatedAt)
            .Select(s => new
            {
                s.Id,
                s.Name,
                s.Prefix,
                s.IsActive,
                s.CreatedAt,
                s.ExpiresAt,
                s.RevokedAt,
                s.LastUsedAt
            })
            .ToListAsync();

        return Ok(secrets);
    }

    // ── POST /api/admin/oauth-clients/{clientId}/secrets ─────────────────────

    [HttpPost("{clientId:guid}/secrets")]
    public async Task<IActionResult> CreateSecret(
        Guid clientId,
        [FromBody] CreateSecretRequest request)
    {
        var client = await dbContext.Set<OAuthClient>()
            .FirstOrDefaultAsync(c => c.Id == clientId);

        if (client is null) return NotFound(new { error = "client_not_found" });

        if (client.ClientType == ClientType.Public)
            return BadRequest(new { error = "public_client_no_secrets" });

        var (rawSecret, prefix) = GenerateSecret();

        var entity = new ClientSecret
        {
            Id               = Guid.NewGuid(),
            ClientInternalId = clientId,
            Name             = request.Name,
            Prefix           = prefix,
            SecretHash       = BCrypt.Net.BCrypt.HashPassword(rawSecret, workFactor: 12),
            IsActive         = true,
            CreatedAt        = DateTime.UtcNow,
            ExpiresAt        = request.ExpiresAt
        };

        dbContext.Set<ClientSecret>().Add(entity);
        await dbContext.SaveChangesAsync();

        var (actorId, actorEmail) = Actor();
        await auditService.LogAsync(
            action: AuditAction.ClientSecretCreated,
            actorEmail: actorEmail,
            actorId: actorId,
            resourceType: "ClientSecret",
            resourceId: entity.Id.ToString(),
            resourceName: $"{client.Name} / {prefix}",
            metadata: $"{{\"name\":\"{request.Name}\",\"prefix\":\"{prefix}\"}}",
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        logger.LogInformation("Admin {Actor} created secret {Prefix} for client {ClientId}",
            actorEmail, prefix, clientId);

        // Return the raw secret ONCE — it cannot be retrieved again
        return Ok(new
        {
            entity.Id,
            entity.Prefix,
            Secret = rawSecret,   // raw value returned exactly once
            entity.CreatedAt,
            entity.ExpiresAt,
            Warning = "Store this secret securely — it will not be shown again."
        });
    }

    // ── DELETE /api/admin/oauth-clients/{clientId}/secrets/{secretId} ────────

    [HttpDelete("{clientId:guid}/secrets/{secretId:guid}")]
    public async Task<IActionResult> RevokeSecret(Guid clientId, Guid secretId)
    {
        var secret = await dbContext.Set<ClientSecret>()
            .FirstOrDefaultAsync(s => s.Id == secretId && s.ClientInternalId == clientId);

        if (secret is null) return NotFound(new { error = "secret_not_found" });
        if (!secret.IsActive) return Ok(new { ok = true, note = "already_revoked" });

        secret.IsActive  = false;
        secret.RevokedAt = DateTime.UtcNow;
        await dbContext.SaveChangesAsync();

        var (actorId, actorEmail) = Actor();
        await auditService.LogAsync(
            action: AuditAction.ClientSecretRevoked,
            actorEmail: actorEmail,
            actorId: actorId,
            resourceType: "ClientSecret",
            resourceId: secretId.ToString(),
            resourceName: secret.Prefix,
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        logger.LogWarning("Admin {Actor} revoked secret {Prefix} for client {ClientId}",
            actorEmail, secret.Prefix, clientId);

        return NoContent();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    // Format: spc_{12-char prefix}.{32-char random}
    private static (string rawSecret, string prefix) GenerateSecret()
    {
        var prefixBytes = RandomNumberGenerator.GetBytes(9);  // 12 base64url chars
        var bodyBytes   = RandomNumberGenerator.GetBytes(24); // 32 base64url chars

        var prefix = "spc_" + Base64UrlEncode(prefixBytes);
        var body   = Base64UrlEncode(bodyBytes);
        return ($"{prefix}.{body}", prefix);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

public record CreateSecretRequest(string? Name, DateTime? ExpiresAt);
