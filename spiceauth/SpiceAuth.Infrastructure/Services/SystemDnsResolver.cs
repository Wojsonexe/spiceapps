using System.Net;
using SpiceAuth.Application.Services.Security;

namespace SpiceAuth.Infrastructure.Services;

public sealed class SystemDnsResolver : IDnsResolver
{
    public Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress) =>
        Dns.GetHostAddressesAsync(hostNameOrAddress);
}
