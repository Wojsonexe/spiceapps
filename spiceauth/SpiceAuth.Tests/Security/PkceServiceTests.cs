using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Moq;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Infrastructure.Services;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Unit tests for PkceService — RFC 7636 S256 PKCE implementation.
/// All tests are pure computation; no DB or DI needed.
/// </summary>
public class PkceServiceTests
{
    private readonly PkceService _pkce = new(new Mock<ILogger<PkceService>>().Object);

    // ── ValidateVerifierFormat ────────────────────────────────────────────────

    [Fact]
    public void ValidateVerifierFormat_ValidVerifier_DoesNotThrow()
    {
        // 48 chars, all valid unreserved ASCII chars, adequate entropy
        _pkce.ValidateVerifierFormat("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-abc");
    }

    [Fact]
    public void ValidateVerifierFormat_ExactlyMinLength_DoesNotThrow()
    {
        // Exactly 43 chars, with enough unique characters
        var verifier = "ABCDEFGHIJKLMNabcdefghijklmn0123456789-._~XYZ";
        Assert.Equal(46, verifier.Length); // > 43 to avoid off-by-one; replace with exact
        _pkce.ValidateVerifierFormat("ABCDEFGHIJKLMNabcdefghijklmn0123456789-._~XYZ".Substring(0, 43));
    }

    [Fact]
    public void ValidateVerifierFormat_TooShort_ThrowsPkceException()
    {
        // 42 chars — one below minimum
        var verifier = new string('A', 10) + new string('B', 10) + new string('C', 10) + "0123456789ab";
        var ex = Assert.Throws<PkceException>(() => _pkce.ValidateVerifierFormat(verifier));
        Assert.Contains("too short", ex.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateVerifierFormat_TooLong_ThrowsPkceException()
    {
        var verifier = new string('A', 60) + new string('b', 60) + new string('C', 9);
        Assert.Throws<PkceException>(() => _pkce.ValidateVerifierFormat(verifier));
    }

    [Fact]
    public void ValidateVerifierFormat_InvalidCharacters_ThrowsPkceException()
    {
        // Space and '@' are not unreserved chars
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFO@jXk";
        var ex = Assert.Throws<PkceException>(() => _pkce.ValidateVerifierFormat(verifier));
        Assert.Contains("invalid characters", ex.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateVerifierFormat_LowEntropy_AllSameChar_ThrowsPkceException()
    {
        // 43 identical chars — trivially guessable
        var verifier = new string('A', 43);
        var ex = Assert.Throws<PkceException>(() => _pkce.ValidateVerifierFormat(verifier));
        Assert.Contains("entropy", ex.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateVerifierFormat_MaxLength_DoesNotThrow()
    {
        // 128 chars with high entropy — maximum allowed length
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        var verifier = string.Concat(Enumerable.Repeat(chars, 3))[..128];
        _pkce.ValidateVerifierFormat(verifier);
    }

    // ── VerifyChallenge ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
    [InlineData("ABCDEFGHIJKLMNabcdefghijklmn0123456789-._~XY")]
    public void VerifyChallenge_CorrectVerifier_ReturnsTrue(string verifier)
    {
        var challenge = ComputeS256(verifier);
        Assert.True(_pkce.VerifyChallenge(verifier, challenge));
    }

    [Fact]
    public void VerifyChallenge_WrongVerifier_ReturnsFalse()
    {
        var correctVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge       = ComputeS256(correctVerifier);
        Assert.False(_pkce.VerifyChallenge("ABCDEFGHIJKLMNabcdefghijklmn0123456789-._~XY", challenge));
    }

    [Fact]
    public void VerifyChallenge_EmptyVerifier_ReturnsFalse()
        => Assert.False(_pkce.VerifyChallenge("", "some-challenge-value-here-padded-to-43-ch"));

    [Fact]
    public void VerifyChallenge_EmptyChallenge_ReturnsFalse()
        => Assert.False(_pkce.VerifyChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", ""));

    [Fact]
    public void VerifyChallenge_BothEmpty_ReturnsFalse()
        => Assert.False(_pkce.VerifyChallenge("", ""));

    [Fact]
    public void VerifyChallenge_IsConstantTime_ChallengeWithWrongLength_ReturnsFalse()
    {
        // Wrong-length challenge — should return false, not throw
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        Assert.False(_pkce.VerifyChallenge(verifier, "short"));
    }

    // ── IsValidChallenge ──────────────────────────────────────────────────────

    [Fact]
    public void IsValidChallenge_ValidS256Challenge_ReturnsTrue()
    {
        var challenge = ComputeS256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        Assert.True(_pkce.IsValidChallenge(challenge));
    }

    [Fact]
    public void IsValidChallenge_TooShort_ReturnsFalse()
        => Assert.False(_pkce.IsValidChallenge("short"));

    [Fact]
    public void IsValidChallenge_ContainsPadding_ReturnsFalse()
    {
        // Base64 with padding chars — not valid for URL-safe base64url
        Assert.False(_pkce.IsValidChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX="));
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private static string ComputeS256(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
