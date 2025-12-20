using System.Security.Cryptography;

namespace SpiceAuth.Application.Interfaces;

/// <summary>
/// Service for managing RSA keys used for JWT signing.
/// </summary>
public interface IKeyManagementService
{
    /// <summary>
    /// Get the current RSA private key for signing tokens.
    /// </summary>
    RSA GetPrivateKey();
    
    /// <summary>
    /// Get the current RSA public key for token validation.
    /// </summary>
    RSA GetPublicKey();
    
    /// <summary>
    /// Get the current key ID (kid) for JWT header.
    /// </summary>
    string GetCurrentKeyId();
    
    /// <summary>
    /// Get public key in JWK format for JWKS endpoint.
    /// </summary>
    string GetPublicKeyJwk();
}