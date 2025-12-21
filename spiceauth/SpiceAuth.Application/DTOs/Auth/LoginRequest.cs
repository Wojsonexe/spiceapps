namespace SpiceAuth.Application.DTOs.Auth;

public record LoginRequest
{
    public string Email { get; init; } = null!;
    public string Password { get; init; } = null!;
    public bool RememberMe { get; init; }
}