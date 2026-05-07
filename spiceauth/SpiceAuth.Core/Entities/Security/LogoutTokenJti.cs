namespace SpiceAuth.Core.Entities.Security;

/// <summary>
/// Replay-protection store for OIDC back-channel logout tokens.
/// Once a jti is recorded here, the same logout token is rejected as a replay.
/// TTL-cleanup is handled by SessionCleanupService.
/// </summary>
public class LogoutTokenJti
{
    public string Jti { get; set; } = string.Empty;
    public DateTime UsedAt { get; set; } = DateTime.UtcNow;
}
