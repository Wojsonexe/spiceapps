using System.Net;

namespace SpiceAuth.Application.Services.Security;

/// <summary>
/// Thin abstraction over <see cref="System.Net.Dns"/> for testability.
/// </summary>
public interface IDnsResolver
{
    Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress);
}
