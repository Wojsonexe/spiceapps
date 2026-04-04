namespace SpiceAuth.Application.DTOs.OAuth;

public record UpdateClientRequest
{
    public string Name { get; init; } = null!;
    public string? Description { get; init; }
    public List<string> RedirectUris { get; init; } = new();
    public List<string>? PostLogoutRedirectUris { get; init; }
    public List<string> AllowedScopes { get; init; } = new();
    public bool RequireConsent { get; init; }
    public bool RequirePkce { get; init; }
}