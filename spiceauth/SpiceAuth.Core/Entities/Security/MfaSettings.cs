using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Core.Entities.Security;

public class MfaSettings
{
    public Guid UserId { get; set; }
    public bool IsEnabled { get; set; }
    public string? TotpSecret { get; set; } // Encrypted
    
    // JSON array of hashed backup codes
    public string? BackupCodes { get; set; }
    
    public DateTime? EnabledAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    
    // Navigation
    public User User { get; set; } = null!;
}