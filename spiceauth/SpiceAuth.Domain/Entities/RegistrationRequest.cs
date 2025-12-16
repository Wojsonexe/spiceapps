using SpiceAuth.Domain.Enums;
using SpiceAuth.Domain.Interfaces;

namespace SpiceAuth.Domain.Entities;

/// <summary>
/// Represents a pending user registration that requires admin approval.
/// </summary>
public class RegistrationRequest : IEntity
{
    public Guid Id { get; set; }
    
    // Applicant Data
    public string Email { get; set; } = null!;
    public string NormalizedEmail { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string PasswordHash { get; set; } = null!;
    public string SourceApp { get; set; } = null!; // e.g., "spicehub", "discord", "spiceapi"
    
    // Status
    public RegistrationRequestStatus Status { get; set; } = RegistrationRequestStatus.Pending;
    
    // Timestamps
    public DateTime SubmittedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ReviewedAt { get; set; }
    
    // Review Data
    public Guid? ReviewedByUserId { get; set; }
    public User? ReviewedBy { get; set; }
    public string? RejectionReason { get; set; }
    
    // Request Metadata
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    
    // Discord-specific (if registration via Discord OAuth)
    public string? DiscordId { get; set; }
    public string? DiscordUsername { get; set; }
    public string? DiscordDiscriminator { get; set; }
    public string? DiscordAvatar { get; set; }
}