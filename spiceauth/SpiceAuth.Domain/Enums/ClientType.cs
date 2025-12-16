namespace SpiceAuth.Domain.Enums;

/// <summary>
/// Type of OAuth 2.0 client.
/// </summary>
public enum ClientType
{
    /// <summary>
    /// Confidential client - can securely store client secret (e.g., web server).
    /// </summary>
    Confidential = 0,
    
    /// <summary>
    /// Public client - cannot store secret (e.g., SPA, mobile app). Requires PKCE.
    /// </summary>
    Public = 1,
    
    /// <summary>
    /// Service client - backend-to-backend (client credentials flow only).
    /// </summary>
    Service = 2
}