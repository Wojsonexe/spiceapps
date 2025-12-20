using System.Text.Json.Serialization;

namespace SpiceAuth.Application.DTOs.Responses;

/// <summary>
/// OAuth 2.0 token response.
/// </summary>
public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = null!;
    
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";
    
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
    
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }
    
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }
    
    [JsonPropertyName("id_token")]
    public string? IdToken { get; set; } // OIDC
}