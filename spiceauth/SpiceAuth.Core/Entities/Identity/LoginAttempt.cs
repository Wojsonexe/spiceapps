namespace SpiceAuth.Core.Entities.Identity;

/// <summary>
/// Tracks failed login attempts for account lockout
/// </summary>
public class LoginAttempt : BaseEntity
{
    public Guid? UserId { get; set; }
    public ApplicationUser? User { get; set; }
    
    public string Email { get; set; } = null!;
    public string IpAddress { get; set; } = null!;
    public string? UserAgent { get; set; }
    
    public bool IsSuccessful { get; set; }
    public DateTime AttemptedAt { get; set; }
    
    public string? FailureReason { get; set; }
}