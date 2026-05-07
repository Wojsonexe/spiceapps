using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Tests.Helpers;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Verifies refresh token security properties:
/// - Normal rotation: one token in, one token out
/// - Reuse detection: used token presented again triggers family revocation
/// - Expiry enforcement
/// - Revocation enforcement
/// - Family revocation completeness
/// </summary>
public class RefreshTokenSecurityTests : OAuthServiceTestBase
{
    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_ValidToken_ReturnsNewAccessToken()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var rawToken = "valid-refresh-token-abcdef1234567890abcdef12";
        SeedRefreshToken(client, user, rawToken);

        var response = await Service.RefreshTokenAsync(rawToken, client.Id);

        Assert.NotNull(response);
        Assert.Equal("test-access-token", response.AccessToken);
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task Refresh_ValidToken_MarksOriginalAsUsed()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var rawToken = "mark-used-token-abcdef1234567890abcdef12345";
        var seeded   = SeedRefreshToken(client, user, rawToken);

        await Service.RefreshTokenAsync(rawToken, client.Id);

        var stored = await Db.Set<RefreshToken>().FindAsync(seeded.Id);
        Assert.True(stored!.IsUsed);
    }

    // ── Reuse detection ───────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_SameTokenTwice_SecondCallThrowsReuseDetected()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var rawToken = "reuse-refresh-token-abcdef1234567890abcdef1";
        SeedRefreshToken(client, user, rawToken);

        // First use is legitimate
        await Service.RefreshTokenAsync(rawToken, client.Id);

        // Second use with same raw token — reuse detected
        await Assert.ThrowsAsync<RefreshTokenReuseDetectedException>(() =>
            Service.RefreshTokenAsync(rawToken, client.Id));
    }

    [Fact]
    public async Task Refresh_ReuseDetected_RevokesEntireTokenFamily()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var familyId = Guid.NewGuid();
        var rawToken = "family-revoke-token-abcdef1234567890abcdef";

        // Seed the token as part of a specific family
        SeedRefreshToken(client, user, rawToken, familyId: familyId);

        // Seed a sibling token in the same family (simulates a previous rotation)
        SeedRefreshToken(client, user, "sibling-token-1234567890abcdef12345678901", familyId: familyId);

        // First use succeeds
        await Service.RefreshTokenAsync(rawToken, client.Id);

        // Reuse attempt
        await Assert.ThrowsAsync<RefreshTokenReuseDetectedException>(() =>
            Service.RefreshTokenAsync(rawToken, client.Id));

        // Entire family must now be revoked
        var familyTokens = await Db.Set<RefreshToken>()
            .Where(t => t.FamilyId == familyId)
            .ToListAsync();

        Assert.NotEmpty(familyTokens);
        Assert.True(familyTokens.All(t => t.IsRevoked),
            "All tokens in the family must be revoked after reuse detection");
    }

    [Fact]
    public async Task Refresh_ReuseDetected_TriggersSessionRevocation()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var rawToken = "session-revoke-token-abcdef1234567890abcde";
        SeedRefreshToken(client, user, rawToken);

        // First use
        await Service.RefreshTokenAsync(rawToken, client.Id);

        // Reuse attempt
        await Assert.ThrowsAsync<RefreshTokenReuseDetectedException>(() =>
            Service.RefreshTokenAsync(rawToken, client.Id));

        // RevokeAllUserSessionsAsync should have been called once (for the reuse event)
        MockFederation.Verify(
            f => f.RevokeAllUserSessionsAsync(user.Id),
            Moq.Times.Once);
    }

    // ── Expiry ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_ExpiredToken_ThrowsInvalidOperation()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var rawToken = "expired-token-abcdef1234567890abcdef123456";
        SeedRefreshToken(client, user, rawToken, expired: true);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Service.RefreshTokenAsync(rawToken, client.Id));
    }

    // ── Revocation ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_RevokedToken_ThrowsInvalidOperation()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var rawToken = "revoked-token-abcdef1234567890abcdef12345678";
        SeedRefreshToken(client, user, rawToken, isRevoked: true);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Service.RefreshTokenAsync(rawToken, client.Id));
    }

    // ── Unknown token ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_UnknownToken_ThrowsInvalidOperation()
    {
        var client = SeedClient();
        SetupUser();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Service.RefreshTokenAsync("completely-unknown-token-xyz-123456789012345", client.Id));
    }
}
