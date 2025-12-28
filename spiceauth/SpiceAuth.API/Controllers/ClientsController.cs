using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Application.Services.OAuth;

namespace SpiceAuth.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ClientsController(IOAuthService oauthService) : ControllerBase
{
    private readonly IOAuthService _oauthService = oauthService;

    /// <summary>
    /// Register new OAuth client (Developer Portal)
    /// TODO: Add authentication requirement
    /// </summary>
    [HttpPost("register")]
    [ProducesResponseType(typeof(ClientRegistrationResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<ClientRegistrationResponse>> RegisterClient(
        [FromBody] RegisterClientRequest request)
    {
        // TODO: Get authenticated user ID from JWT
        var userId = Guid.NewGuid(); // TEMPORARY

        if (string.IsNullOrWhiteSpace(request.ClientName))
        {
            return BadRequest(new { error = "Client name is required" });
        }

        if (request.RedirectUris == null || !request.RedirectUris.Any())
        {
            return BadRequest(new { error = "At least one redirect URI is required" });
        }

        try
        {
            var response = await _oauthService.RegisterClientAsync(request, userId);
            
            return CreatedAtAction(
                nameof(GetClient),
                new { clientId = response.ClientId },
                response);
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Get client details
    /// TODO: Add authentication + authorization
    /// </summary>
    [HttpGet("{clientId}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<object>> GetClient(string clientId)
    {
        var client = await _oauthService.GetClientByClientIdAsync(clientId);
        
        if (client == null)
        {
            return NotFound();
        }

        return Ok(new
        {
            client_id = client.ClientId,
            name = client.Name,
            description = client.Description,
            client_type = client.ClientType.ToString(),
            redirect_uris = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.RedirectUris),
            allowed_scopes = System.Text.Json.JsonSerializer.Deserialize<string[]>(client.AllowedScopes),
            requires_pkce = client.RequirePkce,
            requires_consent = client.RequireConsent,
            is_active = client.IsActive,
            created_at = client.CreatedAt
        });
    }

    /// <summary>
    /// Get all clients for authenticated user
    /// TODO: Add authentication
    /// </summary>
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<ActionResult<object>> GetMyClients()
    {
        // TODO: Get authenticated user ID
        var userId = Guid.NewGuid(); // TEMPORARY

        var clients = await _oauthService.GetUserClientsAsync(userId);

        return Ok(clients.Select(c => new
        {
            client_id = c.ClientId,
            name = c.Name,
            client_type = c.ClientType.ToString(),
            is_active = c.IsActive,
            created_at = c.CreatedAt
        }));
    }

    /// <summary>
    /// Delete/deactivate client
    /// TODO: Add authentication
    /// </summary>
    [HttpDelete("{clientId}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult> DeleteClient(string clientId)
    {
        // TODO: Get authenticated user ID
        var userId = Guid.NewGuid(); // TEMPORARY

        var client = await _oauthService.GetClientByClientIdAsync(clientId);
        if (client == null)
        {
            return NotFound();
        }

        var success = await _oauthService.DeleteClientAsync(client.Id, userId);
        
        if (!success)
        {
            return NotFound();
        }

        return NoContent();
    }
}