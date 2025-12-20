namespace SpiceAuth.Application.DTOs.Requests;

/// <summary>
/// OAuth 2.0 token request (from form data).
/// Supports multiple grant types.
/// </summary>
public class TokenRequest
{
    public string GrantType { get; set; } = null!;
    
    // For authorization_code grant
    public string? Code { get; set; }
    public string? RedirectUri { get; set; }
    public string? CodeVerifier { get; set; } // PKCE
    
    // For refresh_token grant
    public string? RefreshToken { get; set; }
    
    // For all grants
    public string ClientId { get; set; } = null!;
    public string? ClientSecret { get; set; }
    public string? Scope { get; set; }
}