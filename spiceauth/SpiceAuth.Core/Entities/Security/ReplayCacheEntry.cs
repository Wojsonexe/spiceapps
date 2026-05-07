namespace SpiceAuth.Core.Entities.Security;

/// <summary>
/// Generic replay-protection store for authorization codes and other short-lived identifiers.
/// Entries are TTL-expired; the SessionCleanupService prunes stale rows every 30 minutes.
/// </summary>
public class ReplayCacheEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>"{bucket}:{key}" composite key used for uniqueness.</summary>
    public string EntryKey  { get; set; } = null!;

    public string Bucket    { get; set; } = null!;
    public DateTime RecordedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt  { get; set; }
}
