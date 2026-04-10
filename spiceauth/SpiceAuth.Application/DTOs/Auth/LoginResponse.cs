using System.Text.Json.Serialization;

namespace SpiceAuth.Application.DTOs.Auth;

public class LoginResponse
{
    public bool Success { get; set; }
    public string? Message { get; set; }
    public bool RequiresMfa { get; set; }
    public bool RequiresEmailVerification { get; set; }

    [JsonPropertyName("accessToken")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("refreshToken")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("expiresIn")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("tokenType")]
    public string? TokenType { get; set; } = "Bearer";

    [JsonPropertyName("mfaToken")]
    public string? MfaToken { get; set; }
}