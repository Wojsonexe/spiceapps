namespace SpiceAuth.Core.Entities.OAuth;

public class FederationDispatchAttempt
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FederationDispatchId { get; set; }

    public DateTime AttemptedAt { get; set; } = DateTime.UtcNow;
    public int  HttpStatusCode  { get; set; }
    public bool Success         { get; set; }
    public string? ErrorMessage { get; set; }
    public long DurationMs      { get; set; }

    public FederationDispatch Dispatch { get; set; } = null!;
}
