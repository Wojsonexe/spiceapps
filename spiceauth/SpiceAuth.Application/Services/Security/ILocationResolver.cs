namespace SpiceAuth.Application.Services.Security;

/// <summary>
/// Optional geo-location resolution for session context.
/// Default implementation returns null (no-op). Swap for a GeoLite2 or IP-API backed
/// implementation without changing the caller.
/// </summary>
public interface ILocationResolver
{
    /// <summary>
    /// Resolves an approximate location string (e.g. "Warsaw, PL") from an IP address.
    /// Returns null when resolution is unavailable or disabled.
    /// </summary>
    ValueTask<string?> ResolveAsync(string? ipAddress);
}
