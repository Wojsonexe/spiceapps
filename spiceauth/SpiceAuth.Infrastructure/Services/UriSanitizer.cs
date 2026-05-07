using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Services.Security;

namespace SpiceAuth.Infrastructure.Services;

/// <summary>
/// SSRF-safe URI validator.
///
/// Checks performed in order:
///   1. URI must be a valid absolute URI.
///   2. Scheme must be http or https; HTTPS is required in Production.
///   3. If the host is an IP literal, it is checked against blocked ranges immediately.
///   4. DNS is resolved; every returned IP address must be globally routable.
///
/// Blocked address ranges:
///   - Loopback      127.0.0.0/8, ::1/128
///   - RFC 1918      10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
///   - Link-local    169.254.0.0/16, fe80::/10
///   - IPv6 ULA      fc00::/7
///   - CG-NAT        100.64.0.0/10
///   - Multicast     224.0.0.0/4
///   - Reserved      240.0.0.0/4, 0.0.0.0/8
/// </summary>
public sealed class UriSanitizer(
    IHostEnvironment env,
    IDnsResolver dns,
    ILogger<UriSanitizer> logger) : IUriSanitizer
{
    private static readonly IPNetwork[] BlockedNetworks =
    [
        IPNetwork.Parse("127.0.0.0/8"),
        IPNetwork.Parse("::1/128"),
        IPNetwork.Parse("10.0.0.0/8"),
        IPNetwork.Parse("172.16.0.0/12"),
        IPNetwork.Parse("192.168.0.0/16"),
        IPNetwork.Parse("169.254.0.0/16"),
        IPNetwork.Parse("100.64.0.0/10"),
        IPNetwork.Parse("224.0.0.0/4"),
        IPNetwork.Parse("240.0.0.0/4"),
        IPNetwork.Parse("0.0.0.0/8"),
        IPNetwork.Parse("fc00::/7"),
        IPNetwork.Parse("fe80::/10"),
    ];

    public async Task<UriValidationResult> ValidateAsync(string uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
            return UriValidationResult.Fail("URI must not be empty");

        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed))
            return UriValidationResult.Fail($"'{uri}' is not a valid absolute URI");

        if (parsed.Scheme != "https" && parsed.Scheme != "http")
            return UriValidationResult.Fail($"URI scheme '{parsed.Scheme}' is not allowed; only http and https are permitted");

        if (env.IsProduction() && parsed.Scheme != "https")
            return UriValidationResult.Fail("URI must use HTTPS in production");

        // Fast path: IP literal — check without DNS
        if (IPAddress.TryParse(parsed.Host, out var literalIp))
        {
            var mapped = literalIp.IsIPv4MappedToIPv6 ? literalIp.MapToIPv4() : literalIp;
            if (IsBlocked(mapped))
                return UriValidationResult.Fail(
                    $"URI host '{parsed.Host}' is a private/reserved address — SSRF protection rejected");
        }

        // DNS resolution — every resolved address must be globally routable
        try
        {
            var addresses = await dns.GetHostAddressesAsync(parsed.Host);

            if (addresses.Length == 0)
                return UriValidationResult.Fail($"Host '{parsed.Host}' did not resolve to any IP address");

            foreach (var addr in addresses)
            {
                var mapped = addr.IsIPv4MappedToIPv6 ? addr.MapToIPv4() : addr;
                if (IsBlocked(mapped))
                {
                    logger.LogWarning("SSRF blocked: {Uri} resolved to private address {Ip}", uri, mapped);
                    return UriValidationResult.Fail(
                        $"Host '{parsed.Host}' resolves to a private/reserved address ({mapped})");
                }
            }
        }
        catch (SocketException ex)
        {
            logger.LogWarning("SSRF: DNS resolution failed for '{Host}': {Message}", parsed.Host, ex.Message);
            return UriValidationResult.Fail($"Host '{parsed.Host}' could not be resolved: {ex.Message}");
        }

        return UriValidationResult.Ok();
    }

    private static bool IsBlocked(IPAddress addr) =>
        BlockedNetworks.Any(net => net.Contains(addr));
}
