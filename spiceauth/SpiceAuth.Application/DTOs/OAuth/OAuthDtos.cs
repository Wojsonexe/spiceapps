namespace SpiceAuth.Application.DTOs.OAuth;

// Authorization request
public record AuthorizationRequest
{
    public string ResponseType { get; init; } = null!;
    public string ClientId { get; init; } = null!;
    public string? RedirectUri { get; init; }
    public string? Scope { get; init; }
    public string? State { get; init; }
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
    public string? Nonce { get; init; }
    public string? ResponseMode { get; init; }
}

// Token request
public record TokenRequest
{
    public string GrantType { get; init; } = null!;
    public string? Code { get; init; }
    public string? RedirectUri { get; init; }
    public string ClientId { get; init; } = null!;
    public string? ClientSecret { get; init; }
    public string? CodeVerifier { get; init; }
    public string? RefreshToken { get; init; }
    public string? Scope { get; init; }
}

// Token response
public record TokenResponse
{
    public string AccessToken { get; init; } = null!;
    public string TokenType { get; init; } = "Bearer";
    public int ExpiresIn { get; init; }
    public string? RefreshToken { get; init; }
    public string? IdToken { get; init; }
    public string? Scope { get; init; }
}

// Client registration
public record ClientRegistrationRequest
{
    public string ClientName { get; init; } = null!;
    public string? Description { get; init; }
    public List<string> RedirectUris { get; init; } = new();
    public List<string> PostLogoutRedirectUris { get; init; } = new();
    public string ClientType { get; init; } = "web";
    public List<string> AllowedScopes { get; init; } = new();
}

public record ClientRegistrationResponse
{
    public string ClientId { get; init; } = null!;
    public string ClientSecret { get; init; } = null!;
    public string ClientName { get; init; } = null!;
    public DateTime CreatedAt { get; init; }
}