using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Core.Entities.Security;

public class MfaSettings
{
    public Guid UserId { get; set; }                    // PK = FK do ApplicationUser (1:1)
    public bool IsEnabled { get; set; }
    public string? TotpSecret { get; set; }             // Encrypted at rest
    public string? BackupCodes { get; set; }            // JSON array of hashed codes
    public DateTime? EnabledAt { get; set; }
    public DateTime? LastUsedAt { get; set; }

    // Navigation
    public ApplicationUser User { get; set; } = null!;
}