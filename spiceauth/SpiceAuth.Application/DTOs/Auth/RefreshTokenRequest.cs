namespace SpiceAuth.Application.DTOs.Auth;

public record RefreshTokenRequest
{
    public string RefreshToken { get; init; } = null!;
}