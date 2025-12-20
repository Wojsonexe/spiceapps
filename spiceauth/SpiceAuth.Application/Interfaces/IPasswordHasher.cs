namespace SpiceAuth.Application.Interfaces;

/// <summary>
/// Service for hashing and verifying passwords using Argon2id.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hash a password using Argon2id with automatic salt generation.
    /// </summary>
    string HashPassword(string password);
    
    /// <summary>
    /// Verify a password against a stored hash.
    /// </summary>
    bool VerifyPassword(string hash, string password);
}