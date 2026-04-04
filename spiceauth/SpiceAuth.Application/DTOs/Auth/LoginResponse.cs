namespace SpiceAuth.Application.DTOs.Auth;

public record LoginResponse
{
    public bool Success { get; init; }
    public string? Message { get; init; }
    public bool RequiresMfa { get; init; }
    public bool RequiresEmailVerification { get; init; }
    public string? MfaToken { get; init; }
    public string? AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public Guid? UserId { get; init; }
    public string? Email { get; init; }
    public string? Username { get; init; }
}