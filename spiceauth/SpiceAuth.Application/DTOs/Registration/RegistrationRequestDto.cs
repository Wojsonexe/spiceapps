namespace SpiceAuth.Application.DTOs.Registration;

public record CreateRegistrationRequest
{
    public string Email { get; init; } = null!;
    public string Username { get; init; } = null!;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? Password { get; init; }
}

public record RegistrationRequestDto
{
    public Guid Id { get; init; }
    public string Email { get; init; } = null!;
    public string Username { get; init; } = null!;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string Status { get; init; } = null!;
    public DateTime RequestedAt { get; init; }
    public DateTime? ProcessedAt { get; init; }
    public string? RejectionReason { get; init; }
}

public record ApproveRegistrationRequest
{
    public Guid RequestId { get; init; }
    public string? Notes { get; init; }
}

public record RejectRegistrationRequest
{
    public Guid RequestId { get; init; }
    public string Reason { get; init; } = null!;
}