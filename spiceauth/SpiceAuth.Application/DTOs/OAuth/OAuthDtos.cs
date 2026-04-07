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
public record OAuthError
{
    public string Error { get; init; } = null!;
    public string? ErrorDescription { get; init; }
    public string? ErrorUri { get; init; }
    public string? State { get; init; }
}

public record ConsentRequest
{
    public string ClientId { get; init; } = null!;
    public string RedirectUri { get; init; } = null!;
    public string Scope { get; init; } = null!;
    public string State { get; init; } = "";
    public string CodeChallenge { get; init; } = "";
    public string CodeChallengeMethod { get; init; } = "";
    public string Nonce { get; init; } = "";
    public bool Approved { get; init; }
}

public record OAuthErrorResponse(string Error, string? ErrorDescription = null)
{
    public string Error { get; init; } = Error;
    public string? ErrorDescription { get; init; } = ErrorDescription;
}