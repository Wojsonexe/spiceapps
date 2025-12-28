namespace SpiceAuth.Application.DTOs.OAuth;

public record RegisterClientRequest
{
    public string ClientName { get; init; } = null!;
    public string? Description { get; init; }
    public List<string> RedirectUris { get; init; } = new();
    public List<string>? PostLogoutRedirectUris { get; init; }
    public string ClientType { get; init; } = "web"; // web, mobile, service
    public List<string>? Scopes { get; init; }
}

public record ClientRegistrationResponse
{
    public string ClientId { get; init; } = null!;
    public string ClientSecret { get; init; } = null!;
    public string ClientName { get; init; } = null!;
    public List<string> RedirectUris { get; init; } = new();
    public List<string> AllowedScopes { get; init; } = new();
    public bool RequiresPkce { get; init; }
    public int AccessTokenLifetime { get; init; }
    public int RefreshTokenLifetime { get; init; }
    public DateTime CreatedAt { get; init; }
}