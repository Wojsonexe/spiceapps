namespace SpiceAuth.Application.DTOs.Auth;

public record LoginResponse
{
    public bool Success { get; init; }
    public string? Message { get; init; }
    public bool RequiresMfa { get; init; }
    public string? MfaToken { get; init; }
    public UserDto? User { get; init; }
}