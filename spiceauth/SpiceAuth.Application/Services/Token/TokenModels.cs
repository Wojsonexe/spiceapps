using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Services.Token;

public class TokenRequest
{
    public Guid UserId { get; set; }
    public Guid ClientId { get; set; }
    public string? Scope { get; set; }
    public string[]? Roles { get; set; }
    public Guid? OrganizationId { get; set; }
    public string? Nonce { get; set; }
}

public record TokenResult
{
    public string AccessToken { get; init; } = null!;
    public string TokenType { get; init; } = "Bearer";
    public int ExpiresIn { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdToken { get; init; }
    public string Scope { get; init; } = null!;
}

public class JwksResponse
{
    public List<JwkKey> Keys { get; set; } = new();
}

public class JwkKey
{
    public string Kty { get; set; } = "RSA";
    public string Use { get; set; } = "sig";
    public string Kid { get; set; } = null!;
    public string Alg { get; set; } = "RS256";
    public string N { get; set; } = null!;
    public string E { get; set; } = null!;
}