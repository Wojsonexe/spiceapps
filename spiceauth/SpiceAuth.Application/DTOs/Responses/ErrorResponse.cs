using System.Text.Json.Serialization;

namespace SpiceAuth.Application.DTOs.Responses;

/// <summary>
/// OAuth 2.0 error response (RFC 6749).
/// </summary>
public class ErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; set; } = null!;
    
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
    
    [JsonPropertyName("error_uri")]
    public string? ErrorUri { get; set; }
}

// Common error codes
public static class OAuthErrors
{
    public const string InvalidRequest = "invalid_request";
    public const string InvalidClient = "invalid_client";
    public const string InvalidGrant = "invalid_grant";
    public const string UnauthorizedClient = "unauthorized_client";
    public const string UnsupportedGrantType = "unsupported_grant_type";
    public const string InvalidScope = "invalid_scope";
}