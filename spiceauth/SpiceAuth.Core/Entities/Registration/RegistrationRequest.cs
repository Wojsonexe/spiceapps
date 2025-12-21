using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Registration;

public class RegistrationRequest : BaseEntity
{
    public string Email { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    
    public RegistrationStatus Status { get; set; }
    public DateTime RequestedAt { get; set; }
    public DateTime? ProcessedAt { get; set; }
    
    public Guid? ProcessedByUserId { get; set; }
    public string? RejectionReason { get; set; }
    
    // External provider info (if registered via Discord/Google/GitHub)
    public string? ExternalProvider { get; set; }
    public string? ExternalProviderId { get; set; }
    
    public string? Notes { get; set; }
}