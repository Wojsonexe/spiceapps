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
    public int ExpiresIn { get; init; }
}