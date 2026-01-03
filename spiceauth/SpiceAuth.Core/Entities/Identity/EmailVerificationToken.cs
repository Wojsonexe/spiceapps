namespace SpiceAuth.Core.Entities.Identity;

/// <summary>
/// Token used for email verification
/// </summary>
public class EmailVerificationToken : BaseEntity
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    
    public string Token { get; set; } = null!;
    public string Email { get; set; } = null!;
    
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
    public DateTime? UsedAt { get; set; }
    
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// Token used for password reset
/// </summary>
public class PasswordResetToken : BaseEntity
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    
    public string Token { get; set; } = null!;
    public string Email { get; set; } = null!;
    
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
    public DateTime? UsedAt { get; set; }
    
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

/// <summary>
/// Tracks failed login attempts for account lockout
/// </summary>
public class LoginAttempt : BaseEntity
{
    public Guid? UserId { get; set; }
    public User? User { get; set; }
    
    public string Email { get; set; } = null!;
    public string IpAddress { get; set; } = null!;
    public string? UserAgent { get; set; }
    
    public bool IsSuccessful { get; set; }
    public DateTime AttemptedAt { get; set; }
    
    public string? FailureReason { get; set; }
}