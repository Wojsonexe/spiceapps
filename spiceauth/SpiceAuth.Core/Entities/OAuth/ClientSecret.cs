namespace SpiceAuth.Core.Entities.OAuth;

/// <summary>
/// Versioned client secret supporting overlap windows during rotation.
/// Multiple active secrets per client allow graceful transition periods.
/// Secret format: spc_{prefix}.{random} — prefix stored unencrypted for O(1) lookup.
/// </summary>
public class ClientSecret
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ClientInternalId { get; set; }

    /// <summary>Optional human label set at creation (e.g. "CI/CD pipeline key").</summary>
    public string? Name { get; set; }

    /// <summary>
    /// The short prefix of the raw secret (before the dot separator).
    /// Stored plaintext for fast lookup — NOT secret by itself.
    /// Example: "spc_aB3dEf7gHi" from "spc_aB3dEf7gHi.xxxx..."
    /// </summary>
    public string Prefix { get; set; } = null!;

    /// <summary>BCrypt hash of the full raw secret (including prefix).</summary>
    public string SecretHash { get; set; } = null!;

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }

    public OAuthClient Client { get; set; } = null!;
}
