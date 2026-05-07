using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Services.Security;

namespace SpiceAuth.Infrastructure.Services;

/// <summary>
/// Trusted-proxy-aware IP extraction.
///
/// Config key: <c>ReverseProxy:TrustedNetworks</c> — comma-separated CIDR blocks.
/// Defaults to loopback + RFC 1918 when not configured.
///
/// Algorithm:
/// 1. If the direct connection IP is in the trusted proxy list, walk X-Forwarded-For
///    right-to-left, skipping trusted proxy IPs, to find the first untrusted (real client) IP.
/// 2. If the connection IP is NOT trusted, the connection IP itself is the client IP.
///    X-Forwarded-For is ignored entirely (spoof prevention).
/// </summary>
public sealed class ClientIpService(
    IConfiguration configuration,
    ILogger<ClientIpService> logger) : IClientIpService
{
    private readonly Lazy<List<IPNetwork>> _trustedNetworks = new(() =>
        LoadTrustedNetworks(configuration, logger));

    public string GetClientIp(string? connectionIp, string? xForwardedFor)
    {
        if (string.IsNullOrWhiteSpace(connectionIp)) return "unknown";

        if (!IPAddress.TryParse(connectionIp, out var connAddr))
            return "unknown";

        // Map IPv4-in-IPv6 to pure IPv4
        if (connAddr.IsIPv4MappedToIPv6)
            connAddr = connAddr.MapToIPv4();

        // Only trust forwarded headers when the direct connection comes from a trusted proxy
        if (!IsTrusted(connAddr))
            return connAddr.ToString();

        // Walk X-Forwarded-For from right to left, skipping trusted proxies
        if (string.IsNullOrWhiteSpace(xForwardedFor))
            return connAddr.ToString();

        var ips = xForwardedFor
            .Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Reverse()
            .ToList();

        foreach (var rawIp in ips)
        {
            if (!IPAddress.TryParse(rawIp, out var addr)) continue;
            if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
            if (!IsTrusted(addr)) return addr.ToString();
        }

        // All forwarded IPs were trusted proxies — fall back to direct connection IP
        return connAddr.ToString();
    }

    private bool IsTrusted(IPAddress addr) =>
        _trustedNetworks.Value.Any(net => net.Contains(addr));

    private static List<IPNetwork> LoadTrustedNetworks(IConfiguration cfg, ILogger logger)
    {
        var networks = new List<IPNetwork>
        {
            // Always trust loopback
            IPNetwork.Parse("127.0.0.0/8"),
            IPNetwork.Parse("::1/128"),
            IPNetwork.Parse("10.0.0.0/8"),       // RFC 1918
            IPNetwork.Parse("172.16.0.0/12"),
            IPNetwork.Parse("192.168.0.0/16")
        };

        var configured = cfg["ReverseProxy:TrustedNetworks"]?.Split(',') ?? [];
        foreach (var cidr in configured)
        {
            var trimmed = cidr.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;
            try
            {
                networks.Add(IPNetwork.Parse(trimmed));
            }
            catch
            {
                logger.LogWarning("Invalid CIDR in ReverseProxy:TrustedNetworks: {Cidr}", trimmed);
            }
        }

        return networks;
    }
}
