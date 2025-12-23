using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Services.Token;

public record TokenRequest
{
    public Guid UserId { get; init; }
    public Guid ClientId { get; init; }
    public string Scope { get; init; } = null!;
    public Guid? OrganizationId { get; init; }
    public List<string>? Roles { get; init; }
    public string? Nonce { get; init; }
}

public record TokenResponse
{
    public string AccessToken { get; init; } = null!;
    public string TokenType { get; init; } = "Bearer";
    public int ExpiresIn { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdToken { get; init; }
    public string Scope { get; init; } = null!;
}

public record JwksResponse
{
    public List<JsonWebKey> Keys { get; init; } = [];
}