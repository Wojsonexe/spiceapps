using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Registration;

public class RegistrationRequest : BaseEntity
{
    public string Email { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }

    public RegistrationStatus Status { get; set; }
    public DateTime RequestedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ProcessedAt { get; set; }

    public Guid? ProcessedByUserId { get; set; }
    public string? RejectionReason { get; set; }

    public string? ExternalProvider { get; set; }
    public string? ExternalProviderId { get; set; }
    public string? Notes { get; set; }
}