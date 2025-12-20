using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Interfaces;
using SpiceAuth.Domain.Entities;
using SpiceAuth.Infrastructure.Data;
using SpiceAuth.Infrastructure.Extensions;

namespace SpiceAuth.Infrastructure.Services;

/// <summary>
/// Handles OAuth client validation and authorization.
/// </summary>
public class ClientService : IClientService
{
    private readonly SpiceAuthDbContext _context;
    private readonly ILogger<ClientService> _logger;

    public ClientService(
        SpiceAuthDbContext context,
        ILogger<ClientService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<OAuthClient?> ValidateClientCredentialsAsync(string clientId, string clientSecret)
    {
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            return null;

        var client = await GetClientByIdAsync(clientId);
        if (client == null || !client.IsActive)
        {
            _logger.LogWarning("Client not found or inactive: {ClientId}", clientId);
            return null;
        }

        // Hash provided secret and compare
        var hashedSecret = HashClientSecret(clientSecret);
        if (client.ClientSecret != hashedSecret)
        {
            _logger.LogWarning("Invalid client secret for: {ClientId}", clientId);
            return null;
        }

        return client;
    }

    public async Task<OAuthClient?> GetClientByIdAsync(string clientId)
    {
        return await _context.OAuthClients
            .FirstOrDefaultAsync(c => c.ClientId == clientId);
    }

    public bool IsClientAllowedScope(OAuthClient client, string requestedScope)
    {
        if (string.IsNullOrWhiteSpace(requestedScope))
            return true; // No scope requested = allow

        var allowedScopes = client.GetAllowedScopes();
        var requestedScopes = requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // All requested scopes must be in allowed list
        return requestedScopes.All(scope => 
            allowedScopes.Contains(scope, StringComparer.OrdinalIgnoreCase));
    }

    public bool IsRedirectUriValid(OAuthClient client, string redirectUri)
    {
        if (string.IsNullOrWhiteSpace(redirectUri))
            return false;

        var allowedUris = client.GetRedirectUris();
        return allowedUris.Any(uri => 
            uri.Equals(redirectUri, StringComparison.OrdinalIgnoreCase));
    }

    private static string HashClientSecret(string secret)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}