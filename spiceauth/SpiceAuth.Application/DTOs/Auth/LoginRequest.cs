namespace SpiceAuth.Application.DTOs.Auth;

public record LoginRequest
{
    public string Login { get; init; } = null!;
    public string Password { get; init; } = null!;
    public bool RememberMe { get; init; }
}