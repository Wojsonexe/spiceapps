using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using SpiceAuth.API.Services;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Core.Entities.Authorization;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(AuthenticationSchemes = "Bearer", Roles = "Admin")]
public class AdminController(
    IAuditService auditService,
    IIdentityStore identity,
    ILogger<AdminController> logger,
    DbContext context) : ControllerBase
{
    private readonly IAuditService   _auditService = auditService;
    private readonly IIdentityStore  _identity     = identity;
    private readonly ILogger<AdminController> _logger = logger;
    private readonly DbContext _context = context;

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

    // ── Role management ───────────────────────────────────────────────────────

    [HttpGet("roles")]
    public async Task<ActionResult<object>> GetRoles()
    {
        var roles = await _context.Set<Role>()
            .OrderBy(r => r.Name)
            .Select(r => new { r.Id, r.Name, r.Description, r.IsSystemRole })
            .ToListAsync();

        return Ok(roles);
    }

    [HttpGet("users/{id:guid}/roles")]
    public async Task<ActionResult<object>> GetUserRoles(Guid id)
    {
        var user = await _identity.GetUserAsync(id);
        if (user == null) return NotFound(new { error = "User not found" });

        var roles = await _context.Set<UserRole>()
            .Where(ur => ur.UserId == id)
            .Include(ur => ur.Role)
            .Select(ur => new { ur.Role.Id, ur.Role.Name, ur.Role.Description, ur.AssignedAt })
            .ToListAsync();

        return Ok(roles);
    }

    [HttpPost("users/{id:guid}/roles/{roleName}")]
    public async Task<ActionResult> AssignRole(Guid id, string roleName)
    {
        var (actorId, actorEmail) = GetActor();

        var user = await _identity.GetUserAsync(id);
        if (user == null) return NotFound(new { error = "User not found" });

        var role = await _context.Set<Role>()
            .FirstOrDefaultAsync(r => r.NormalizedName == roleName.ToUpperInvariant());
        if (role == null) return NotFound(new { error = "Role not found" });

        var exists = await _context.Set<UserRole>()
            .AnyAsync(ur => ur.UserId == id && ur.RoleId == role.Id);
        if (exists) return Conflict(new { error = "User already has this role" });

        _context.Set<UserRole>().Add(new UserRole
        {
            UserId = id,
            RoleId = role.Id,
            AssignedByUserId = actorId,
        });
        await _context.SaveChangesAsync();

        await _auditService.LogAsync(
            action: AuditAction.UserRoleChanged,
            actorEmail: actorEmail,
            actorId: actorId,
            resourceType: "UserRole",
            resourceId: id.ToString(),
            resourceName: $"{user.UserName} → {role.Name}",
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        _logger.LogInformation("Admin {Actor} assigned role {Role} to user {UserId}", actorEmail, role.Name, id);
        return NoContent();
    }

    [HttpDelete("users/{id:guid}/roles/{roleName}")]
    public async Task<ActionResult> RemoveRole(Guid id, string roleName)
    {
        var (actorId, actorEmail) = GetActor();

        var user = await _identity.GetUserAsync(id);
        if (user == null) return NotFound(new { error = "User not found" });

        var role = await _context.Set<Role>()
            .FirstOrDefaultAsync(r => r.NormalizedName == roleName.ToUpperInvariant());
        if (role == null) return NotFound(new { error = "Role not found" });

        var userRole = await _context.Set<UserRole>()
            .FirstOrDefaultAsync(ur => ur.UserId == id && ur.RoleId == role.Id);
        if (userRole == null) return NotFound(new { error = "User does not have this role" });

        _context.Set<UserRole>().Remove(userRole);
        await _context.SaveChangesAsync();

        await _auditService.LogAsync(
            action: AuditAction.UserRoleChanged,
            actorEmail: actorEmail,
            actorId: actorId,
            resourceType: "UserRole",
            resourceId: id.ToString(),
            resourceName: $"{user.UserName} ✕ {role.Name}",
            ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString());

        _logger.LogInformation("Admin {Actor} removed role {Role} from user {UserId}", actorEmail, role.Name, id);
        return NoContent();
    }
}
