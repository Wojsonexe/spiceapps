using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Core.Enums;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/clients")]
[Authorize(AuthenticationSchemes = "Bearer")]
public class ClientsController(
    IOAuthService oauthService,
    IAuditService auditService,
    ILogger<ClientsController> logger) : ControllerBase
{
    private readonly IOAuthService _oauthService = oauthService;
    private readonly IAuditService _auditService = auditService;
    private readonly ILogger<ClientsController> _logger = logger;

    private Guid? GetUserId()
    {
        var claim = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(claim, out var id) ? id : null;
    }

    private string GetEmail() => User.FindFirstValue(ClaimTypes.Email) ?? "unknown";
    private string Ip() => HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    private static string FormatDate(DateTime dt) =>
        (dt.Kind == DateTimeKind.Utc ? dt : DateTime.SpecifyKind(dt, DateTimeKind.Utc)).ToString("O");

    private static string[] DeserializeJson(string? json) =>
        string.IsNullOrEmpty(json)
            ? []
            : System.Text.Json.JsonSerializer.Deserialize<string[]>(json) ?? [];

    [HttpPost("register")]
    public async Task<ActionResult<ClientRegistrationResponse>> RegisterClient(
        [FromBody] RegisterClientRequest request)
    {
        var userId = GetUserId();
        if (userId is null)
            return Unauthorized(new { error = "Invalid authentication token" });

        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Client name is required" });

        if (request.RedirectUris == null || !request.RedirectUris.Any())
            return BadRequest(new { error = "At least one redirect URI is required" });

        if (request.AllowedScopes == null || !request.AllowedScopes.Any())
            return BadRequest(new { error = "At least one scope is required" });

        try
        {
            var response = await _oauthService.RegisterClientAsync(request, userId.Value);

            await _auditService.LogAsync(
                action: AuditAction.ClientRegistered,
                actorEmail: GetEmail(),
                actorId: userId,
                resourceType: "Client",
                resourceId: response.ClientId,
                resourceName: request.Name,
                ipAddress: Ip());

            _logger.LogInformation("OAuth client registered: {ClientId} by user {UserId}",
                response.ClientId, userId);

            return CreatedAtAction(nameof(GetClient), new { clientId = response.ClientId }, response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error registering OAuth client for user {UserId}", userId);
            return StatusCode(500, new { error = "An error occurred while registering the client" });
        }
    }

    [HttpGet]
    public async Task<ActionResult<object>> GetMyClients()
    {
        var userId = GetUserId();
        if (userId is null)
            return Unauthorized(new { error = "Invalid authentication token" });

        var clients = await _oauthService.GetUserClientsAsync(userId.Value);

        return Ok(clients.Select(c => new
        {
            clientId = c.ClientId,
            name = c.Name,
            description = c.Description,
            clientType = c.ClientType.ToString(),
            redirectUris = DeserializeJson(c.RedirectUris),
            allowedScopes = DeserializeJson(c.AllowedScopes),
            requireConsent = c.RequireConsent,
            requirePkce = c.RequirePkce,
            isActive = c.IsActive,
            createdAt = FormatDate(c.CreatedAt)
        }));
    }

    [HttpGet("{clientId}")]
    public async Task<ActionResult<object>> GetClient(string clientId)
    {
        var userId = GetUserId();
        if (userId is null)
            return Unauthorized(new { error = "Invalid authentication token" });

        var client = await _oauthService.GetClientByClientIdAsync(clientId);
        if (client == null)
            return NotFound(new { error = "Client not found" });

        if (client.CreatedByUserId != userId.Value && !User.IsInRole("Admin"))
            return Forbid();

        return Ok(new
        {
            clientId = client.ClientId,
            name = client.Name,
            description = client.Description,
            clientType = client.ClientType.ToString(),
            redirectUris = DeserializeJson(client.RedirectUris),
            allowedScopes = DeserializeJson(client.AllowedScopes),
            requireConsent = client.RequireConsent,
            requirePkce = client.RequirePkce,
            isActive = client.IsActive,
            createdAt = FormatDate(client.CreatedAt),
            updatedAt = client.UpdatedAt.HasValue ? FormatDate(client.UpdatedAt.Value) : null
        });
    }

    [HttpPut("{clientId}")]
    public async Task<ActionResult<object>> UpdateClient(
        string clientId,
        [FromBody] UpdateClientRequest request)
    {
        var userId = GetUserId();
        if (userId is null)
            return Unauthorized(new { error = "Invalid authentication token" });

        var client = await _oauthService.GetClientByClientIdAsync(clientId);
        if (client == null)
            return NotFound(new { error = "Client not found" });

        if (client.CreatedByUserId != userId.Value && !User.IsInRole("Admin"))
            return Forbid();

        if (string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { error = "Client name is required" });

        if (request.RedirectUris == null || !request.RedirectUris.Any())
            return BadRequest(new { error = "At least one redirect URI is required" });

        try
        {
            var updated = await _oauthService.UpdateClientAsync(client.Id, request, userId.Value);

            await _auditService.LogAsync(
                action: AuditAction.ClientUpdated,
                actorEmail: GetEmail(),
                actorId: userId,
                resourceType: "Client",
                resourceId: clientId,
                resourceName: updated.Name,
                ipAddress: Ip());

            return Ok(new
            {
                clientId = updated.ClientId,
                name = updated.Name,
                description = updated.Description,
                clientType = updated.ClientType.ToString(),
                redirectUris = DeserializeJson(updated.RedirectUris),
                allowedScopes = DeserializeJson(updated.AllowedScopes),
                requireConsent = updated.RequireConsent,
                requirePkce = updated.RequirePkce,
                isActive = updated.IsActive,
                createdAt = FormatDate(updated.CreatedAt),
                updatedAt = updated.UpdatedAt.HasValue ? FormatDate(updated.UpdatedAt.Value) : null
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpPost("{clientId}/rotate-secret")]
    public async Task<ActionResult<object>> RotateSecret(string clientId)
    {
        var userId = GetUserId();
        if (userId is null)
            return Unauthorized(new { error = "Invalid authentication token" });

        var client = await _oauthService.GetClientByClientIdAsync(clientId);
        if (client == null)
            return NotFound(new { error = "Client not found" });

        if (client.CreatedByUserId != userId.Value && !User.IsInRole("Admin"))
            return Forbid();

        if (client.ClientType == ClientType.Public)
            return BadRequest(new { error = "Public clients do not use client secrets" });

        try
        {
            var newSecret = await _oauthService.RotateClientSecretAsync(client.Id, userId.Value);

            await _auditService.LogAsync(
                action: AuditAction.ClientSecretRotated,
                actorEmail: GetEmail(),
                actorId: userId,
                resourceType: "Client",
                resourceId: clientId,
                resourceName: client.Name,
                ipAddress: Ip());

            return Ok(new
            {
                clientId = client.ClientId,
                clientSecret = newSecret,
                rotatedAt = DateTime.UtcNow.ToString("O")
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpPut("{clientId}/status")]
    public async Task<ActionResult<object>> SetClientStatus(
        string clientId,
        [FromBody] SetClientStatusRequest request)
    {
        var userId = GetUserId();
        if (userId is null)
            return Unauthorized(new { error = "Invalid authentication token" });

        var client = await _oauthService.GetClientByClientIdAsync(clientId);
        if (client == null)
            return NotFound(new { error = "Client not found" });

        if (client.CreatedByUserId != userId.Value && !User.IsInRole("Admin"))
            return Forbid();

        await _oauthService.SetClientStatusAsync(client.Id, request.IsActive, userId.Value);

        await _auditService.LogAsync(
            action: AuditAction.ClientStatusChanged,
            actorEmail: GetEmail(),
            actorId: userId,
            resourceType: "Client",
            resourceId: clientId,
            resourceName: client.Name,
            metadata: request.IsActive ? "Activated" : "Deactivated",
            ipAddress: Ip());

        return Ok(new { clientId = client.ClientId, isActive = request.IsActive });
    }

    [HttpDelete("{clientId}")]
    public async Task<ActionResult> DeleteClient(string clientId)
    {
        var userId = GetUserId();
        if (userId is null)
            return Unauthorized(new { error = "Invalid authentication token" });

        var client = await _oauthService.GetClientByClientIdAsync(clientId);
        if (client == null)
            return NotFound(new { error = "Client not found" });

        if (client.CreatedByUserId != userId.Value && !User.IsInRole("Admin"))
            return Forbid();

        var success = await _oauthService.DeleteClientAsync(client.Id, userId.Value);
        if (!success)
            return NotFound(new { error = "Client not found" });

        await _auditService.LogAsync(
            action: AuditAction.ClientDeleted,
            actorEmail: GetEmail(),
            actorId: userId,
            resourceType: "Client",
            resourceId: clientId,
            resourceName: client.Name,
            ipAddress: Ip());

        return NoContent();
    }
}
