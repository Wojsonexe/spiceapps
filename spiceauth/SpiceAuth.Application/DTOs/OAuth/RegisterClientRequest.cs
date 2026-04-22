using System.Text.Json.Serialization;

public record RegisterClientRequest
{
    public string Name { get; init; } = null!;
    public string? Description { get; init; }

    [JsonPropertyName("clientType")]
    public string ClientType { get; init; } = "Confidential";

    [JsonPropertyName("redirectUris")]
    public List<string> RedirectUris { get; init; } = new();

    [JsonPropertyName("postLogoutRedirectUris")]
    public List<string>? PostLogoutRedirectUris { get; init; }

    [JsonPropertyName("allowedScopes")]
    public List<string> AllowedScopes { get; init; } = new();

    [JsonPropertyName("requireConsent")]
    public bool RequireConsent { get; init; } = true;

    [JsonPropertyName("requirePkce")]
    public bool RequirePkce { get; init; } = true;
}