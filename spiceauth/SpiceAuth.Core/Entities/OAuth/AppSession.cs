namespace SpiceAuth.Core.Entities.OAuth;

public class AppSession
{
    public Guid Id { get; set; }
    public Guid GlobalSessionId { get; set; }

    /// <summary>Registered app name — must match the app's configured AppName claim.</summary>
    public string AppName { get; set; } = string.Empty;

    /// <summary>The session ID the app assigned to this user locally.</summary>
    public string? LocalSessionId { get; set; }

    /// <summary>URI SpiceAuth will POST a logout_token to when the global session is revoked.</summary>
    public string BackchannelLogoutUri { get; set; } = string.Empty;

    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAt { get; set; } = DateTime.UtcNow;

    public GlobalSession GlobalSession { get; set; } = null!;
}
