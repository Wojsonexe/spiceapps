using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Application.Services.Federation;

public interface IFederationService
{
    /// <summary>Creates a new GlobalSession for the given user. Called once on successful login.</summary>
    Task<GlobalSession> CreateGlobalSessionAsync(Guid userId, string? ipAddress, string? userAgent);

    /// <summary>Returns the active GlobalSession for the given sid, or null if revoked/expired.</summary>
    Task<GlobalSession?> GetActiveGlobalSessionAsync(string sid);

    /// <summary>Marks the GlobalSession as revoked. Idempotent.</summary>
    Task RevokeGlobalSessionAsync(string sid);

    /// <summary>
    /// Upserts an AppSession registration for the given sid.
    /// Called by registered apps after the user logs in there.
    /// Throws InvalidOperationException if the GlobalSession does not exist or is revoked.
    /// </summary>
    Task RegisterAppSessionAsync(
        string sid,
        string appName,
        string? localSessionId,
        string backchannelLogoutUri,
        string clientId,
        string clientSecret);

    /// <summary>
    /// Revokes the GlobalSession for sid, then dispatches a logout_token to every
    /// registered AppSession. Errors in individual dispatches are logged but do not
    /// prevent other apps from receiving the token.
    /// </summary>
    Task RevokeAndDispatchAsync(string sid, string clientId, string clientSecret);

    /// <summary>
    /// Returns all GlobalSessions for the given user (active and expired/revoked).
    /// Ordered by CreatedAt descending.
    /// </summary>
    Task<IReadOnlyList<GlobalSession>> GetUserSessionsAsync(Guid userId);

    /// <summary>
    /// Revokes all active GlobalSessions for the given user and dispatches
    /// backchannel logout tokens to every registered AppSession.
    /// Used on refresh-token reuse detection to terminate all sessions system-wide.
    /// </summary>
    Task RevokeAllUserSessionsAsync(Guid userId);
}
