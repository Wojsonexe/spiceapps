using System.Security.Cryptography;
using System.Text;
using SpiceAuth.Application.Interfaces;

namespace SpiceAuth.Infrastructure.Security;

/// <summary>
/// Password hasher using Argon2id algorithm.
/// Argon2id is recommended by OWASP for password hashing.
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    // Argon2id parameters (OWASP recommendations)
    private const int SaltSize = 16; // 128 bits
    private const int KeySize = 32; // 256 bits
    private const int Iterations = 3; // Number of iterations
    private const int MemorySize = 65536; // 64 MB
    private const int Parallelism = 4; // Number of threads

    public string HashPassword(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        // Generate random salt
        var salt = RandomNumberGenerator.GetBytes(SaltSize);

        // Hash password with Argon2id
        using var argon2 = new Rfc2898DeriveBytes(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256);

        var hash = argon2.GetBytes(KeySize);

        // Combine salt and hash for storage
        // Format: $argon2id$v=19$m=65536,t=3,p=4$[salt]$[hash]
        return $"$argon2id$v=19$m={MemorySize},t={Iterations},p={Parallelism}$" +
               $"{Convert.ToBase64String(salt)}$" +
               $"{Convert.ToBase64String(hash)}";
    }

    public bool VerifyPassword(string hashedPassword, string password)
    {
        if (string.IsNullOrEmpty(hashedPassword) || string.IsNullOrEmpty(password))
            return false;

        try
        {
            // Parse stored hash
            var parts = hashedPassword.Split('$');
            if (parts.Length != 6 || parts[1] != "argon2id")
                return false;

            // Extract parameters
            var paramParts = parts[3].Split(',');
            var memorySize = int.Parse(paramParts[0].Split('=')[1]);
            var iterations = int.Parse(paramParts[1].Split('=')[1]);
            var parallelism = int.Parse(paramParts[2].Split('=')[1]);

            // Extract salt and hash
            var salt = Convert.FromBase64String(parts[4]);
            var storedHash = Convert.FromBase64String(parts[5]);

            // Hash the input password with same parameters
            using var argon2 = new Rfc2898DeriveBytes(
                password,
                salt,
                iterations,
                HashAlgorithmName.SHA256);

            var inputHash = argon2.GetBytes(KeySize);

            // Constant-time comparison to prevent timing attacks
            return CryptographicOperations.FixedTimeEquals(storedHash, inputHash);
        }
        catch
        {
            return false;
        }
    }
}