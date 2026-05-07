namespace SpiceAuth.Application.Services.RateLimit;

/// <summary>
/// Per-key failure tracking for brute-force protection on auth endpoints.
/// Implementations must be thread-safe (registered as Singleton).
/// </summary>
public interface IRateLimitService
{
    /// <summary>Returns true if the key is currently locked out.</summary>
    bool IsBlocked(string bucket, string key);

    /// <summary>Records a failure. Applies a lock after <paramref name="maxAttempts"/> failures.</summary>
    void RecordFailure(string bucket, string key, int maxAttempts = 5, TimeSpan? lockDuration = null);

    /// <summary>Clears the failure counter on successful authentication.</summary>
    void ClearFailures(string bucket, string key);
}
