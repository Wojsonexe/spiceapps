namespace SpiceAuth.Application.Services.Security;

/// <summary>
/// Distributed-safe replay-protection cache.
/// Implementations must be thread-safe and survive node restarts (i.e. backed by
/// persistent storage or Redis — not process memory).
///
/// The in-memory fallback is provided for single-node / development scenarios.
/// </summary>
public interface IReplayCache
{
    /// <summary>
    /// Records that a token identifier (jti, code) has been consumed.
    /// Returns true if this is the FIRST recording (caller may proceed).
    /// Returns false if already recorded (replay detected — caller must reject).
    /// </summary>
    Task<bool> TryRecordAsync(string bucket, string key, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Checks whether a token identifier is already recorded without consuming it.</summary>
    Task<bool> IsRecordedAsync(string bucket, string key, CancellationToken ct = default);
}
