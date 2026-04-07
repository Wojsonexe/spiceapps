namespace SpiceAuth.Core.Entities.Identity;

public class EmailVerificationToken : BaseEntity
{
    public Guid UserId { get; set; }
    public string Token { get; set; } = null!;
    public string Email { get; set; } = null!;
    public DateTime ExpiresAt { get; set; }
    public bool IsUsed { get; set; }
    public DateTime? UsedAt { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    public ApplicationUser User { get; set; } = null!;
}