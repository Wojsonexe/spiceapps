using System.Text;

namespace SpiceAuth.Application.Services.Security;

/// <summary>
/// Secure password hasher using BCrypt with recommended work factor for 2026.
/// Implements timing-attack resistant verification and password strength validation.
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    // 🔒 Work factor 13 recommended for 2026 (OWASP: minimum 10, but 12-14 is better)
    private const int WorkFactor = 13;
    
    // 🔒 Minimum password length (NIST recommends 8+ characters)
    private const int MinPasswordLength = 8;
    
    // 🔒 Maximum password length (prevent DoS via extremely long passwords)
    private const int MaxPasswordLength = 128;

    /// <summary>
    /// Hashes a password using BCrypt with work factor 13.
    /// </summary>
    /// <param name="password">Plain text password to hash</param>
    /// <returns>BCrypt hash string</returns>
    /// <exception cref="ArgumentException">If password is invalid</exception>
    public string HashPassword(string password)
    {
        // 🔒 Validation
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty or whitespace", nameof(password));

        if (password.Length < MinPasswordLength)
            throw new ArgumentException($"Password must be at least {MinPasswordLength} characters long", nameof(password));

        if (password.Length > MaxPasswordLength)
            throw new ArgumentException($"Password cannot exceed {MaxPasswordLength} characters", nameof(password));

        // 🔒 Normalize password (prevent Unicode exploits)
        var normalizedPassword = password.Normalize(NormalizationForm.FormC);

        // 🔒 Hash with BCrypt (automatically salted)
        return BCrypt.Net.BCrypt.HashPassword(normalizedPassword, WorkFactor);
    }

    /// <summary>
    /// Verifies a password against a BCrypt hash using timing-attack resistant comparison.
    /// </summary>
    /// <param name="password">Plain text password to verify</param>
    /// <param name="hash">BCrypt hash to compare against</param>
    /// <returns>True if password matches, false otherwise</returns>
    public bool VerifyPassword(string password, string hash)
    {
        // 🔒 Fast-fail for obviously invalid inputs (but still constant-time for valid format)
        if (string.IsNullOrWhiteSpace(password))
            return ConstantTimeFailure();

        if (string.IsNullOrWhiteSpace(hash))
            return ConstantTimeFailure();

        // 🔒 Length check (prevent DoS)
        if (password.Length < MinPasswordLength || password.Length > MaxPasswordLength)
            return ConstantTimeFailure();

        // 🔒 Validate hash format (BCrypt hashes start with $2a$, $2b$, or $2y$)
        if (!IsValidBCryptHash(hash))
            return ConstantTimeFailure();

        try
        {
            // 🔒 Normalize password (same as hashing)
            var normalizedPassword = password.Normalize(NormalizationForm.FormC);

            // 🔒 BCrypt.Verify is already timing-attack resistant
            return BCrypt.Net.BCrypt.Verify(normalizedPassword, hash);
        }
        catch (BCrypt.Net.SaltParseException)
        {
            // Invalid hash format
            return ConstantTimeFailure();
        }
        catch (Exception)
        {
            // Any other error (corrupted hash, etc.)
            return ConstantTimeFailure();
        }
    }

    /// <summary>
    /// Checks if a password needs rehashing (e.g., work factor too low).
    /// Use this to upgrade hashes when WorkFactor is increased.
    /// </summary>
    /// <param name="hash">BCrypt hash to check</param>
    /// <returns>True if hash should be regenerated</returns>
    public bool NeedsRehash(string hash)
    {
        if (string.IsNullOrWhiteSpace(hash))
            return true;

        try
        {
            // Extract work factor from hash (format: $2a$12$...)
            var parts = hash.Split('$');
            if (parts.Length < 4)
                return true;

            if (int.TryParse(parts[2], out var hashWorkFactor))
            {
                // Rehash if work factor is lower than current
                return hashWorkFactor < WorkFactor;
            }

            return true;
        }
        catch
        {
            return true;
        }
    }

    /// <summary>
    /// Validates password strength (basic checks).
    /// For production, consider using a dedicated library like Zxcvbn.
    /// </summary>
    /// <param name="password">Password to validate</param>
    /// <returns>Tuple of (isValid, errorMessage)</returns>
    public (bool IsValid, string? ErrorMessage) ValidatePasswordStrength(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            return (false, "Password cannot be empty");

        if (password.Length < MinPasswordLength)
            return (false, $"Password must be at least {MinPasswordLength} characters");

        if (password.Length > MaxPasswordLength)
            return (false, $"Password cannot exceed {MaxPasswordLength} characters");

        // 🔒 Check for common patterns (optional, can be more sophisticated)
        var hasLower = password.Any(char.IsLower);
        var hasUpper = password.Any(char.IsUpper);
        var hasDigit = password.Any(char.IsDigit);
        var hasSpecial = password.Any(c => !char.IsLetterOrDigit(c));

        var strengthScore = 0;
        if (hasLower) strengthScore++;
        if (hasUpper) strengthScore++;
        if (hasDigit) strengthScore++;
        if (hasSpecial) strengthScore++;

        if (strengthScore < 3)
            return (false, "Password must contain at least 3 of: lowercase, uppercase, digit, special character");

        // 🔒 Check against common passwords (you'd load this from a file in production)
        if (IsCommonPassword(password))
            return (false, "This password is too common. Please choose a stronger password");

        return (true, null);
    }

    // ════════════════════════════════════════════════════════════════
    // PRIVATE HELPERS
    // ════════════════════════════════════════════════════════════════

    /// <summary>
    /// Constant-time failure to prevent timing attacks on invalid inputs.
    /// Performs a dummy BCrypt verification to maintain constant timing.
    /// </summary>
    private static bool ConstantTimeFailure()
    {
        // 🔒 Perform dummy BCrypt operation to maintain constant time
        // This prevents attackers from determining if input validation failed vs hash mismatch
        try
        {
            BCrypt.Net.BCrypt.Verify("dummy_password_for_timing_consistency", 
                "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW");
        }
        catch { /* ignore */ }

        return false;
    }

    /// <summary>
    /// Validates BCrypt hash format.
    /// </summary>
    private static bool IsValidBCryptHash(string hash)
    {
        if (hash.Length < 59 || hash.Length > 60)
            return false;

        // BCrypt hashes start with $2a$, $2b$, or $2y$ followed by work factor
        return hash.StartsWith("$2a$") || 
               hash.StartsWith("$2b$") || 
               hash.StartsWith("$2y$");
    }

    /// <summary>
    /// Checks if password is in common password list.
    /// In production, load from a file (e.g., top 10k passwords from Have I Been Pwned).
    /// </summary>
    private static bool IsCommonPassword(string password)
    {
        // 🔒 Basic common passwords (expand this list or load from file)
        var commonPasswords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "bailey", "passw0rd", "shadow", "123123", "654321",
            "superman", "qazwsx", "michael", "football", "password1"
        };

        return commonPasswords.Contains(password);
    }
}
