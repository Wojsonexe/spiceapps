using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Tests for UriSanitizer SSRF protection.
/// DNS is mocked via IDnsResolver so tests are deterministic and network-free.
/// </summary>
public class UriSanitizerTests
{
    // ── Helpers ───────────────────────────────────────────────────────────────

    private static UriSanitizer Build(
        IPAddress[]? dnsResults = null,
        bool isProduction = false,
        bool dnsThrows = false)
    {
        var envMock = new Mock<IHostEnvironment>();
        envMock.Setup(e => e.EnvironmentName)
               .Returns(isProduction ? "Production" : "Development");

        var dnsMock = new Mock<IDnsResolver>();
        if (dnsThrows)
        {
            dnsMock.Setup(d => d.GetHostAddressesAsync(It.IsAny<string>()))
                   .ThrowsAsync(new System.Net.Sockets.SocketException());
        }
        else
        {
            dnsMock.Setup(d => d.GetHostAddressesAsync(It.IsAny<string>()))
                   .ReturnsAsync(dnsResults ?? [IPAddress.Parse("93.184.216.34")]); // example.com
        }

        return new UriSanitizer(envMock.Object, dnsMock.Object,
            new Mock<ILogger<UriSanitizer>>().Object);
    }

    // ── Format validation ─────────────────────────────────────────────────────

    [Fact]
    public async Task EmptyUri_Rejected()
    {
        var sut = Build();
        var result = await sut.ValidateAsync("");
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task RelativeUri_Rejected()
    {
        var sut = Build();
        var result = await sut.ValidateAsync("/callback");
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task FtpScheme_Rejected()
    {
        var sut = Build();
        var result = await sut.ValidateAsync("ftp://files.example.com/path");
        Assert.False(result.IsValid);
    }

    // ── HTTPS enforcement in Production ──────────────────────────────────────

    [Fact]
    public async Task Http_InDevelopment_Allowed()
    {
        var sut = Build(isProduction: false);
        var result = await sut.ValidateAsync("http://app.example.com/callback");
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Http_InProduction_Rejected()
    {
        var sut = Build(isProduction: true);
        var result = await sut.ValidateAsync("http://app.example.com/callback");
        Assert.False(result.IsValid);
        Assert.Contains("HTTPS", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Https_InProduction_Allowed()
    {
        var sut = Build(isProduction: true);
        var result = await sut.ValidateAsync("https://app.example.com/callback");
        Assert.True(result.IsValid);
    }

    // ── IP literal rejection (fast path, no DNS needed) ───────────────────────

    [Theory]
    [InlineData("http://127.0.0.1/callback")]            // loopback
    [InlineData("http://10.0.0.1/callback")]             // RFC 1918
    [InlineData("http://192.168.1.1/callback")]          // RFC 1918
    [InlineData("http://172.16.0.5/callback")]           // RFC 1918
    [InlineData("http://169.254.1.1/callback")]          // link-local
    [InlineData("http://[::1]/callback")]                // IPv6 loopback
    public async Task PrivateIpLiteral_Rejected(string uri)
    {
        // DNS mock returns a public IP, but literal IP should be caught before DNS
        var sut = Build(dnsResults: [IPAddress.Parse("93.184.216.34")]);
        var result = await sut.ValidateAsync(uri);
        Assert.False(result.IsValid);
        Assert.Contains("private", result.Error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PublicIpLiteral_Allowed()
    {
        var sut = Build(dnsResults: [IPAddress.Parse("93.184.216.34")]);
        var result = await sut.ValidateAsync("https://93.184.216.34/callback");
        Assert.True(result.IsValid);
    }

    // ── DNS-based rejection (DNS rebinding prevention) ────────────────────────

    [Theory]
    [InlineData("127.0.0.1")]    // loopback
    [InlineData("10.0.0.1")]     // RFC 1918
    [InlineData("192.168.1.100")]// RFC 1918
    [InlineData("172.31.0.1")]   // RFC 1918
    [InlineData("169.254.1.1")]  // APIPA
    public async Task DnsResolvesToPrivateIp_Rejected(string resolvedIp)
    {
        var sut = Build(dnsResults: [IPAddress.Parse(resolvedIp)]);
        var result = await sut.ValidateAsync("https://internal.corp/callback");
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task DnsResolvesToPublicIp_Allowed()
    {
        var sut = Build(dnsResults: [IPAddress.Parse("93.184.216.34")]);
        var result = await sut.ValidateAsync("https://app.example.com/callback");
        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task DnsResolutionFails_Rejected()
    {
        var sut = Build(dnsThrows: true);
        var result = await sut.ValidateAsync("https://no-such-host.invalid/callback");
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task DnsReturnsNoAddresses_Rejected()
    {
        var sut = Build(dnsResults: []);
        var result = await sut.ValidateAsync("https://empty.example.com/callback");
        Assert.False(result.IsValid);
    }

    // ── DNS rebinding: one public + one private IP ────────────────────────────

    [Fact]
    public async Task DnsReturnsMixedPublicAndPrivate_Rejected()
    {
        // If ANY resolved address is private the whole URI is rejected
        var sut = Build(dnsResults:
        [
            IPAddress.Parse("93.184.216.34"),  // public
            IPAddress.Parse("10.0.0.1"),       // private — sneaked in
        ]);
        var result = await sut.ValidateAsync("https://app.example.com/callback");
        Assert.False(result.IsValid);
    }

    // ── Valid public HTTPS URI ─────────────────────────────────────────────────

    [Fact]
    public async Task ValidPublicHttpsUri_Allowed()
    {
        var sut = Build();
        var result = await sut.ValidateAsync("https://app.example.com/callback");
        Assert.True(result.IsValid);
        Assert.Null(result.Error);
    }
}
