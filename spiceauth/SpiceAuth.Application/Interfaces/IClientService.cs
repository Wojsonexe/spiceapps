using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Application.Interfaces;

/// <summary>
/// Service for OAuth client validation and management.
/// </summary>
public interface IClientService
{
    /// <summary>
    /// Validate client credentials (client_id + client_secret).
    /// </summary>
    Task<OAuthClient?> ValidateClientCredentialsAsync(string clientId, string clientSecret);
    
    /// <summary>
    /// Get client by ID.
    /// </summary>
    Task<OAuthClient?> GetClientByIdAsync(string clientId);
    
    /// <summary>
    /// Check if client is allowed to use specific scope(s).
    /// </summary>
    bool IsClientAllowedScope(OAuthClient client, string requestedScope);
    
    /// <summary>
    /// Check if redirect URI is valid for client.
    /// </summary>
    bool IsRedirectUriValid(OAuthClient client, string redirectUri);
}