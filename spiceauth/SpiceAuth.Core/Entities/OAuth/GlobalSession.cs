namespace SpiceAuth.Core.Entities.OAuth;

public class GlobalSession
{
    public Guid Id { get; set; }

    /// <summary>
    /// Globally unique session identifier — propagated to all registered apps as the federation anchor.
    /// </summary>
    public string Sid { get; set; } = string.Empty;

    public Guid UserId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;

    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    /// <summary>Opaque fingerprint (hash of UA + Accept-Language + platform hints). Used for session anomaly detection.</summary>
    public string? DeviceFingerprint { get; set; }

    /// <summary>Best-effort geographic hint derived from IP at session creation time (city/country, not stored precisely).</summary>
    public string? Location { get; set; }

    public ICollection<AppSession> AppSessions { get; set; } = new List<AppSession>();

    public bool IsActive => RevokedAt == null && ExpiresAt > DateTime.UtcNow;
}
