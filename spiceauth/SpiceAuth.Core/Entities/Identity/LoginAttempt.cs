namespace SpiceAuth.Core.Entities.Identity;

public class LoginAttempt : BaseEntity
{
    public Guid? UserId { get; set; }
    public string Email { get; set; } = null!;
    public string IpAddress { get; set; } = null!;
    public string? UserAgent { get; set; }
    public bool IsSuccessful { get; set; }
    public string? FailureReason { get; set; }
    public DateTime AttemptedAt { get; set; } = DateTime.UtcNow;
    public ApplicationUser? User { get; set; }
}