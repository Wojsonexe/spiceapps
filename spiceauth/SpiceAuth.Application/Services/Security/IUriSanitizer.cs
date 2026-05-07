namespace SpiceAuth.Application.Services.Security;

public record UriValidationResult(bool IsValid, string? Error)
{
    public static UriValidationResult Ok()              => new(true, null);
    public static UriValidationResult Fail(string error) => new(false, error);
}

/// <summary>
/// Validates redirect/backchannel URIs for SSRF safety.
/// Resolves DNS before acceptance — prevents DNS-rebinding attacks.
/// </summary>
public interface IUriSanitizer
{
    /// <summary>
    /// Validates a single URI. Rejects private/reserved addresses, enforces HTTPS
    /// in production, and resolves DNS to check all returned IPs.
    /// </summary>
    Task<UriValidationResult> ValidateAsync(string uri);
}
