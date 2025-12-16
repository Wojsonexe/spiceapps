using SpiceAuth.Domain.Entities;
using System.Text.Json;

namespace SpiceAuth.Infrastructure.Extensions;

/// <summary>
/// Extension methods for OAuthClient to work with JSON-stored arrays.
/// </summary>
public static class OAuthClientExtensions
{
    public static List<string> GetRedirectUris(this OAuthClient client)
    {
        try
        {
            return JsonSerializer.Deserialize<List<string>>(client.RedirectUris) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }
    
    public static void SetRedirectUris(this OAuthClient client, List<string> uris)
    {
        client.RedirectUris = JsonSerializer.Serialize(uris);
    }
    
    public static List<string> GetPostLogoutRedirectUris(this OAuthClient client)
    {
        if (string.IsNullOrEmpty(client.PostLogoutRedirectUris))
            return new List<string>();
        
        try
        {
            return JsonSerializer.Deserialize<List<string>>(client.PostLogoutRedirectUris) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }
    
    public static void SetPostLogoutRedirectUris(this OAuthClient client, List<string> uris)
    {
        client.PostLogoutRedirectUris = JsonSerializer.Serialize(uris);
    }
    
    public static List<string> GetAllowedScopes(this OAuthClient client)
    {
        try
        {
            return JsonSerializer.Deserialize<List<string>>(client.AllowedScopes) ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }
    
    public static void SetAllowedScopes(this OAuthClient client, List<string> scopes)
    {
        client.AllowedScopes = JsonSerializer.Serialize(scopes);
    }
    
    public static bool IsRedirectUriAllowed(this OAuthClient client, string redirectUri)
    {
        var allowedUris = client.GetRedirectUris();
        return allowedUris.Any(uri => uri.Equals(redirectUri, StringComparison.OrdinalIgnoreCase));
    }
    
    public static bool IsScopeAllowed(this OAuthClient client, string scope)
    {
        var allowedScopes = client.GetAllowedScopes();
        return allowedScopes.Contains(scope, StringComparer.OrdinalIgnoreCase);
    }
    
    public static bool AreScopesAllowed(this OAuthClient client, string[] requestedScopes)
    {
        var allowedScopes = client.GetAllowedScopes();
        return requestedScopes.All(scope => allowedScopes.Contains(scope, StringComparer.OrdinalIgnoreCase));
    }
}