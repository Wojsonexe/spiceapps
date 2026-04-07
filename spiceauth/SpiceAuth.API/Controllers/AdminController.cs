using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using SpiceAuth.API.Services;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
public class AdminController(
    IAuditService auditService,
    IIdentityStore identity,
    ILogger<AdminController> logger) : ControllerBase
{
    private readonly IAuditService   _auditService = auditService;
    private readonly IIdentityStore  _identity     = identity;
    private readonly ILogger<AdminController> _logger = logger;

    private (Guid? id, string email) GetActor() => (
        Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null,
        User.FindFirstValue(ClaimTypes.Email) ?? "unknown"
    );

    [HttpGet("audit-logs")]
    public async Task<ActionResult<object>> GetAuditLogs(
        [FromQuery] int page          = 1,
        [FromQuery] int pageSize      = 50,
        [FromQuery] string? search    = null,
        [FromQuery] AuditAction? action = null)
    {
        pageSize = Math.Clamp(pageSize, 1, 100);
        var (items, total) = await _auditService.GetLogsAsync(page, pageSize, search, action);

        return Ok(new
        {
            items = items.Select(l => new
            {
                id            = l.Id,
                action        = l.Action.ToString(),
                actorEmail    = l.ActorEmail,
                actorId       = l.UserId,
                resourceType  = l.ResourceType,
                resourceId    = l.ResourceId,
                resourceName  = l.ResourceName,
                meta          = l.Metadata,
                success       = l.Success,
                failureReason = l.FailureReason,
                ipAddress     = l.IpAddress,
                timestamp     = l.Timestamp.ToString("O")
            }),
            total,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling(total / (double)pageSize)
        });
    }

    [HttpGet("users")]
    public async Task<ActionResult<object>> GetUsers(
        [FromQuery] int page       = 1,
        [FromQuery] int pageSize   = 50,
        [FromQuery] string? search = null)
    {
        pageSize = Math.Clamp(pageSize, 1, 100);
        var (users, total) = await _identity.GetUsersAsync(page, pageSize, search);

        return Ok(new
        {
            items = users.Select(u => new
            {
                id              = u.Id,
                email           = u.Email,
                username        = u.UserName,
                firstName       = u.FirstName,
                lastName        = u.LastName,
                isEmailVerified = u.EmailConfirmed,
                isActive        = u.IsActive,
                createdAt       = u.CreatedAt.ToString("O"),
                lastLoginAt     = u.LastLoginAt?.ToString("O")
            }),
            total,
            page,
            pageSize,
            totalPages = (int)Math.Ceiling(total / (double)pageSize)
        });
    }

    [HttpGet("users/{id:guid}")]
    public async Task<ActionResult<object>> GetUser(Guid id)
    {
        var user = await _identity.GetUserAsync(id);
        if (user == null)
            return NotFound(new { error = "User not found" });

        return Ok(new
        {
            id              = user.Id,
            email           = user.Email,
            username        = user.UserName,
            firstName       = user.FirstName,
            lastName        = user.LastName,
            isEmailVerified = user.EmailConfirmed,
            isActive        = user.IsActive,
            isSuspended     = user.IsSuspended,
            createdAt       = user.CreatedAt.ToString("O"),
            lastLoginAt     = user.LastLoginAt?.ToString("O")
        });
    }

    [HttpDelete("users/{id:guid}")]
    public async Task<ActionResult> DeleteUser(Guid id)
    {
        var (actorId, actorEmail) = GetActor();

        var user = await _identity.GetUserAsync(id);
        if (user == null)
            return NotFound(new { error = "User not found" });

        await _identity.DeleteUserAsync(id);

        await _auditService.LogAsync(
            action: AuditAction.UserDeleted,
            actorEmail: actorEmail,
            actorId: actorId,
            resourceType: "User",
            resourceId: id.ToString(),
            resourceName: user.UserName,
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        _logger.LogInformation("Admin {Actor} deleted user {UserId}", actorEmail, id);
        return NoContent();
    }

    [HttpPatch("users/{id:guid}/suspend")]
    public async Task<ActionResult> SuspendUser(Guid id)
    {
        var (actorId, actorEmail) = GetActor();

        var user = await _identity.GetUserAsync(id);
        if (user == null)
            return NotFound(new { error = "User not found" });

        await _identity.SetUserSuspendedAsync(id, true);

        await _auditService.LogAsync(
            action: AuditAction.UserSuspended,
            actorEmail: actorEmail,
            actorId: actorId,
            resourceType: "User",
            resourceId: id.ToString(),
            resourceName: user.UserName,
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        _logger.LogInformation("Admin {Actor} suspended user {UserId}", actorEmail, id);
        return NoContent();
    }

    [HttpPatch("users/{id:guid}/activate")]
    public async Task<ActionResult> ActivateUser(Guid id)
    {
        var (actorId, actorEmail) = GetActor();

        var user = await _identity.GetUserAsync(id);
        if (user == null)
            return NotFound(new { error = "User not found" });

        await _identity.SetUserSuspendedAsync(id, false);

        await _auditService.LogAsync(
            action: AuditAction.UserActivated,
            actorEmail: actorEmail,
            actorId: actorId,
            resourceType: "User",
            resourceId: id.ToString(),
            resourceName: user.UserName,
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        _logger.LogInformation("Admin {Actor} activated user {UserId}", actorEmail, id);
        return NoContent();
    }
    
    [HttpPost("migrate-users")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> MigrateUsers(
        [FromServices] UserMigrationService migrationService)
    {
        _logger.LogWarning("User migration triggered by {UserId}",
            User.FindFirstValue(ClaimTypes.NameIdentifier));

        var report = await migrationService.MigrateAsync();

        return Ok(new
        {
            report.Migrated,
            report.Skipped,
            report.Failed,
            report.Errors
        });
    }
}
