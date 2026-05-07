using Microsoft.EntityFrameworkCore;
using Moq;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Enums;
using SpiceAuth.Tests.Helpers;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Verifies that when an authorization code is replayed (second redemption attempt),
/// the server:
///   1. Revokes all refresh token families for the affected user+client.
///   2. Terminates all global sessions via federation.
///   3. Records a Critical security event.
///   4. Throws AuthorizationCodeReplayException.
///
/// Uses the same InMemory + concurrency-token approach as other unit tests —
/// sequential replay is detected via the early IsUsed check.
/// True concurrent replay (two goroutines racing) is tested in ConcurrentRedemptionTests (SQLite).
/// </summary>
public class AuthCodeReplayContainmentTests : OAuthServiceTestBase
{
    // ── Helper: consume a code once so the second call is a replay ───────────

    private async Task ConsumeCodeAsync(OAuthClient client, AuthorizationCode code)
    {
        await Service.ExchangeAuthorizationCodeAsync(
            code.Code, client.Id, "https://app.test/callback", null);
        // Reset mock invocation counters so the first (successful) call doesn't
        // interfere with assertions about the replay call.
        MockFederation.Invocations.Clear();
        MockSecurityEvents.Invocations.Clear();
    }

    // ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task ReplayDetected_RevokesAllTokenFamilies()
    {
        var client = SeedClient();
        var user   = SetupUser();
        var code   = SeedAuthCode(client, user);

        // Seed two separate families for this user+client
        var fid1 = Guid.NewGuid();
        var fid2 = Guid.NewGuid();
        SeedRefreshToken(client, user, "raw-token-a", familyId: fid1);
        SeedRefreshToken(client, user, "raw-token-b", familyId: fid2);

        // Consume the code once (valid path), then replay it
        await ConsumeCodeAsync(client, code);

        await Assert.ThrowsAsync<AuthorizationCodeReplayException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                code.Code, client.Id, "https://app.test/callback", null));

        // All token families must be revoked
        var tokens = await Db.Set<RefreshToken>().ToListAsync();
        Assert.All(tokens, t => Assert.True(t.IsRevoked));
    }

    [Fact]
    public async Task ReplayDetected_TerminatesGlobalSession()
    {
        var client = SeedClient();
        var user   = SetupUser();
        var code   = SeedAuthCode(client, user);

        await ConsumeCodeAsync(client, code);

        await Assert.ThrowsAsync<AuthorizationCodeReplayException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                code.Code, client.Id, "https://app.test/callback", null));

        // Federation revocation called for the victim user
        MockFederation.Verify(
            f => f.RevokeAllUserSessionsAsync(user.Id),
            Times.Once);
    }

    [Fact]
    public async Task ReplayDetected_EmitsCriticalSecurityEvent()
    {
        var client = SeedClient();
        var user   = SetupUser();
        var code   = SeedAuthCode(client, user);

        await ConsumeCodeAsync(client, code);

        await Assert.ThrowsAsync<AuthorizationCodeReplayException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                code.Code, client.Id, "https://app.test/callback", null));

        MockSecurityEvents.Verify(
            s => s.Record(
                user.Id,
                SecurityEventType.AuthorizationCodeReplay,
                SecurityEventSeverity.Critical,
                It.IsAny<string>(),
                It.IsAny<string?>()),
            Times.Once);
    }

    [Fact]
    public async Task NonExistentCode_DoesNotEmitSecurityEvent_AndThrowsReplay()
    {
        // A probe for a code that never existed — no user info → no containment.
        var client = SeedClient();
        SetupUser();

        await Assert.ThrowsAsync<AuthorizationCodeReplayException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                "nonexistent-code", client.Id, "https://app.test/callback", null));

        MockFederation.Verify(f => f.RevokeAllUserSessionsAsync(It.IsAny<Guid>()), Times.Never);
        MockSecurityEvents.Verify(
            s => s.Record(It.IsAny<Guid>(), SecurityEventType.AuthorizationCodeReplay,
                It.IsAny<SecurityEventSeverity>(), It.IsAny<string>(), It.IsAny<string?>()),
            Times.Never);
    }

    [Fact]
    public async Task ValidExchange_NoContainmentActionsTriggered()
    {
        var client = SeedClient();
        var user   = SetupUser();
        var code   = SeedAuthCode(client, user);

        // First (valid) exchange — must succeed without any containment
        await Service.ExchangeAuthorizationCodeAsync(
            code.Code, client.Id, "https://app.test/callback", null);

        MockFederation.Verify(f => f.RevokeAllUserSessionsAsync(It.IsAny<Guid>()), Times.Never);
        MockSecurityEvents.Verify(
            s => s.Record(It.IsAny<Guid>(), SecurityEventType.AuthorizationCodeReplay,
                It.IsAny<SecurityEventSeverity>(), It.IsAny<string>(), It.IsAny<string?>()),
            Times.Never);
    }
}
