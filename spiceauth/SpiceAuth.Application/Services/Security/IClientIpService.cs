namespace SpiceAuth.Application.Services.Security;

/// <summary>
/// Extracts the real client IP from raw connection data, respecting
/// a configured set of trusted proxy networks and preventing spoofing via
/// X-Forwarded-For injection from untrusted sources.
/// </summary>
public interface IClientIpService
{
    /// <param name="connectionIp">The remote IP of the direct TCP connection (from HttpContext.Connection.RemoteIpAddress).</param>
    /// <param name="xForwardedFor">Raw X-Forwarded-For header value, or null/empty if absent.</param>
    string GetClientIp(string? connectionIp, string? xForwardedFor);
}
