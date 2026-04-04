namespace SpiceAuth.Application.DTOs.Auth;

public record RegisterResponse
{
    public bool Success { get; init; }
    public string? Message { get; init; }
    public Guid? UserId { get; init; }
}