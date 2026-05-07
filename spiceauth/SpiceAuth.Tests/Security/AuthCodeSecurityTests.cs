using SpiceAuth.Application.Exceptions;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Tests.Helpers;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Verifies authorization code security properties:
/// - Single-use enforcement (replay prevention)
/// - Expiry enforcement
/// - Client binding (code for client A cannot be used by client B)
/// - PKCE enforcement (S256 only; plain rejected; mismatch rejected)
/// </summary>
public class AuthCodeSecurityTests : OAuthServiceTestBase
{
    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_ValidCode_ReturnsTokenResponse()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var authCode = SeedAuthCode(client, user);

        var response = await Service.ExchangeAuthorizationCodeAsync(
            authCode.Code, client.Id, authCode.RedirectUri!, null);

        Assert.NotNull(response);
        Assert.Equal("test-access-token", response.AccessToken);
        Assert.NotNull(response.RefreshToken);
    }

    // ── Replay prevention ─────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_SameCodeTwice_SecondThrowsReplay()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var authCode = SeedAuthCode(client, user);

        // First exchange succeeds
        await Service.ExchangeAuthorizationCodeAsync(
            authCode.Code, client.Id, authCode.RedirectUri!, null);

        // Second exchange with same code MUST throw replay exception
        await Assert.ThrowsAsync<AuthorizationCodeReplayException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client.Id, authCode.RedirectUri!, null));
    }

    [Fact]
    public async Task Exchange_NonexistentCode_ThrowsReplay()
    {
        // Unknown code is treated the same as a replayed code to prevent enumeration
        var client = SeedClient();
        SetupUser();

        await Assert.ThrowsAsync<AuthorizationCodeReplayException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                "totally-unknown-code", client.Id, "https://app.test/callback", null));
    }

    // ── Expiry ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_ExpiredCode_ThrowsInvalidGrant()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var authCode = SeedAuthCode(client, user, expired: true);

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client.Id, authCode.RedirectUri!, null));

        Assert.Equal("invalid_grant", ex.Error);
        Assert.Contains("expired", ex.ErrorDescription ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // ── Client binding ────────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_CodeBelongingToOtherClient_ThrowsInvalidGrant()
    {
        var client1  = SeedClient("client-one");
        var client2  = SeedClient("client-two");
        var user     = SetupUser();
        var authCode = SeedAuthCode(client1, user);

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client2.Id, authCode.RedirectUri!, null));

        Assert.Equal("invalid_grant", ex.Error);
    }

    [Fact]
    public async Task Exchange_WrongRedirectUri_ThrowsInvalidGrant()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var authCode = SeedAuthCode(client, user);

        var ex = await Assert.ThrowsAsync<OAuthException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client.Id, "https://evil.attacker.com/callback", null));

        Assert.Equal("invalid_grant", ex.Error);
    }

    // ── PKCE enforcement ──────────────────────────────────────────────────────

    [Fact]
    public async Task Exchange_WithPkce_CorrectVerifier_Succeeds()
    {
        var client    = SeedClient();
        var user      = SetupUser();
        var verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = ComputeS256Challenge(verifier);
        var authCode  = SeedAuthCode(client, user, codeChallenge: challenge);

        var response = await Service.ExchangeAuthorizationCodeAsync(
            authCode.Code, client.Id, authCode.RedirectUri!, verifier);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task Exchange_WithPkce_WrongVerifier_ThrowsPkceException()
    {
        var client    = SeedClient();
        var user      = SetupUser();
        var verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = ComputeS256Challenge(verifier);
        var authCode  = SeedAuthCode(client, user, codeChallenge: challenge);

        await Assert.ThrowsAsync<PkceException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client.Id, authCode.RedirectUri!,
                "ABCDEFGHIJKLMNabcdefghijklmn0123456789-._~XY"));  // wrong — different verifier
    }

    [Fact]
    public async Task Exchange_WithPkce_MissingVerifier_ThrowsPkceException()
    {
        var client    = SeedClient();
        var user      = SetupUser();
        var challenge = ComputeS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        var authCode  = SeedAuthCode(client, user, codeChallenge: challenge);

        // code_verifier must be provided when code_challenge was set
        await Assert.ThrowsAsync<PkceException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client.Id, authCode.RedirectUri!, codeVerifier: null));
    }

    [Fact]
    public async Task Exchange_PlainCodeChallengeMethod_IsRejected()
    {
        // Only S256 is accepted — plain is a timing-oracle risk
        var client  = SeedClient();
        var user    = SetupUser();
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        var authCode = new AuthorizationCode
        {
            Id                  = Guid.NewGuid(),
            Code                = GenerateCode(),
            ClientId            = client.Id,
            UserId              = user.Id,
            RedirectUri         = "https://app.test/callback",
            Scope               = "openid profile",
            CodeChallenge       = verifier,   // plain: challenge == verifier
            CodeChallengeMethod = "plain",
            IsUsed              = false,
            ExpiresAt           = DateTime.UtcNow.AddMinutes(10),
            CreatedAt           = DateTime.UtcNow
        };
        Db.Set<AuthorizationCode>().Add(authCode);
        await Db.SaveChangesAsync();

        await Assert.ThrowsAsync<PkceException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client.Id, authCode.RedirectUri!, verifier));
    }

    [Fact]
    public async Task Exchange_PkceVerifierTooShort_ThrowsPkceException()
    {
        var client    = SeedClient();
        var user      = SetupUser();
        var verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = ComputeS256Challenge(verifier);
        var authCode  = SeedAuthCode(client, user, codeChallenge: challenge);

        // Verifier that's too short to pass format validation
        await Assert.ThrowsAsync<PkceException>(() =>
            Service.ExchangeAuthorizationCodeAsync(
                authCode.Code, client.Id, authCode.RedirectUri!, "short"));
    }
}
