namespace SpiceAuth.Application.DTOs.Auth;

public record MfaChallengeRequest
{
    public required string MfaToken { get; init; }
    public required string Code { get; init; }
}