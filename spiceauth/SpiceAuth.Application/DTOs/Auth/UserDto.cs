namespace SpiceAuth.Application.DTOs.Auth;

public record UserDto
{
    public Guid Id { get; init; }
    public string Email { get; init; } = null!;
    public string Username { get; init; } = null!;
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? ProfilePictureUrl { get; init; }
    public bool IsActive { get; init; }
    public DateTime CreatedAt { get; init; }
}