namespace SpiceAuth.Core.Entities.Identity;

/// <summary>
/// Token used for password reset
/// </summary>
public class PasswordResetToken : BaseEntity
{
    public Guid UserId { get; set; }
    public ApplicationUser User { get; set; } = null!;
    
    public string Token { get; set; } = null!;
    public string Email { get; set; } = null!;
    
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
    public DateTime? UsedAt { get; set; }
    
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}