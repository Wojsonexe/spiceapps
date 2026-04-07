using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Services.Token;

public class TokenRequest
{
    public Guid         UserId         { get; set; }
    public Guid         ClientId       { get; set; }
    public string       Scope          { get; set; } = string.Empty;
    public List<string>? Roles         { get; set; }
    public Guid?        OrganizationId { get; set; }
    public string?      Nonce          { get; set; }
    public string       Audience       { get; set; } = "spiceapi";
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

public record JwksResponse
{
    public List<JsonWebKey> Keys { get; init; } = [];
}