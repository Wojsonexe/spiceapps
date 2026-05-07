using SpiceAuth.Application.Services.Security;

namespace SpiceAuth.Infrastructure.Services;

/// <summary>
/// No-op ILocationResolver. Replace with a GeoLite2/MaxMind or IP-API implementation
/// when geographic session context is needed. No external dependency required by default.
/// </summary>
public sealed class NoOpLocationResolver : ILocationResolver
{
    public ValueTask<string?> ResolveAsync(string? ipAddress) => ValueTask.FromResult<string?>(null);
}
