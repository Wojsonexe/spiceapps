namespace SpiceAuth.Domain.Enums;

/// <summary>
/// PKCE code challenge method (RFC 7636).
/// </summary>
public enum CodeChallengeMethod
{
    /// <summary>
    /// Plain text (not recommended, for legacy clients only).
    /// </summary>
    Plain = 0,
    
    /// <summary>
    /// SHA256 hash (recommended).
    /// </summary>
    S256 = 1
}