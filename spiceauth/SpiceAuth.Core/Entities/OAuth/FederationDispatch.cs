namespace SpiceAuth.Core.Entities.OAuth;

/// <summary>
/// Durable record of a backchannel logout dispatch job.
/// Persisted before the first attempt so no delivery is lost during outages.
/// </summary>
public class FederationDispatch
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid   GlobalSessionId      { get; set; }
    public string Sid                  { get; set; } = null!;
    public string AppName              { get; set; } = null!;
    public string BackchannelLogoutUri { get; set; } = null!;
    public string LogoutToken          { get; set; } = null!;   // pre-generated, stored

    public DispatchStatus Status       { get; set; } = DispatchStatus.Pending;

    public int  AttemptCount          { get; set; } = 0;
    public DateTime? LastAttemptAt    { get; set; }
    public DateTime? NextAttemptAt    { get; set; } = DateTime.UtcNow;
    public DateTime? DeliveredAt      { get; set; }
    public DateTime? DeadLetterAt     { get; set; }

    /// <summary>Idempotency key: prevents duplicate delivery even if the dispatcher runs twice.</summary>
    public string DispatchId          { get; set; } = Guid.NewGuid().ToString("N");

    public DateTime CreatedAt         { get; set; } = DateTime.UtcNow;

    public ICollection<FederationDispatchAttempt> Attempts { get; set; } = new List<FederationDispatchAttempt>();
}

public enum DispatchStatus
{
    Pending    = 0,
    Delivered  = 1,
    Failed     = 2,   // retrying
    DeadLetter = 3    // max retries exceeded
}
