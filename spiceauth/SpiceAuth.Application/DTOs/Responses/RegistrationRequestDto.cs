namespace SpiceAuth.Application.DTOs.Responses;

public class RegistrationRequestDto
{
    public Guid Id { get; set; }
    public string Email { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string SourceApp { get; set; } = null!;
    public string Status { get; set; } = null!;
    public DateTime SubmittedAt { get; set; }
    public DateTime? ReviewedAt { get; set; }
    public string? ReviewedByUsername { get; set; }
    public string? RejectionReason { get; set; }
}