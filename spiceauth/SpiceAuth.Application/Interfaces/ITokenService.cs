using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Application.Interfaces;

/// <summary>
/// Service for generating and validating JWT tokens.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Generate an access token (JWT) for a user.
    /// </summary>
    string GenerateAccessToken(
        User user, 
        string clientId, 
        string scope, 
        List<string> roles);
    
    /// <summary>
    /// Generate an access token for client credentials flow (no user).
    /// </summary>
    string GenerateClientCredentialsToken(
        string clientId, 
        string scope);
    
    /// <summary>
    /// Generate a refresh token (opaque string).
    /// </summary>
    string GenerateRefreshToken();
    
    /// <summary>
    /// Get JWKS (JSON Web Key Set) for public key distribution.
    /// </summary>
    string GetJwks();
}