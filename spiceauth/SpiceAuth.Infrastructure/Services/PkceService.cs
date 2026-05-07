using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Application.Services.Security;

namespace SpiceAuth.Infrastructure.Services;

/// <summary>
/// RFC 7636 PKCE implementation.
/// - Only S256 accepted; plain is explicitly rejected.
/// - Verifier: 43–128 unreserved ASCII chars [A-Za-z0-9._~-]
/// - Challenge: base64url(SHA-256(ASCII(verifier))) — exactly 43 chars
/// - Comparison: constant-time to prevent timing-oracle attacks
/// </summary>
public sealed class PkceService(ILogger<PkceService> logger) : IPkceService
{
    // RFC 7636 §4.1 — unreserved chars + length bounds
    private const int MinVerifierLength = 43;
    private const int MaxVerifierLength = 128;
    private const int ExpectedChallengeLength = 43;   // base64url(32 bytes) with no padding

    private static readonly Regex VerifierRegex =
        new(@"^[A-Za-z0-9\-._~]+$", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    private static readonly Regex ChallengeRegex =
        new(@"^[A-Za-z0-9\-_]+$", RegexOptions.Compiled, TimeSpan.FromMilliseconds(50));

    public void ValidateVerifierFormat(string codeVerifier)
    {
        if (string.IsNullOrEmpty(codeVerifier))
            throw new PkceException("code_verifier is required");

        if (codeVerifier.Length < MinVerifierLength)
            throw new PkceException($"code_verifier too short (min {MinVerifierLength} chars, got {codeVerifier.Length})");

        if (codeVerifier.Length > MaxVerifierLength)
            throw new PkceException($"code_verifier too long (max {MaxVerifierLength} chars)");

        if (!VerifierRegex.IsMatch(codeVerifier))
            throw new PkceException("code_verifier contains invalid characters (must be unreserved ASCII: A-Za-z0-9-._~)");

        // Entropy sanity check — verifier of all same chars is trivially guessable
        var uniqueChars = codeVerifier.Distinct().Count();
        if (uniqueChars < 8)
        {
            logger.LogWarning("PKCE verifier has very low entropy ({Unique} unique chars)", uniqueChars);
            throw new PkceException("code_verifier has insufficient entropy");
        }
    }

    public bool VerifyChallenge(string codeVerifier, string storedChallenge)
    {
        if (string.IsNullOrEmpty(codeVerifier) || string.IsNullOrEmpty(storedChallenge))
            return false;

        // Derive S256 challenge from the submitted verifier
        var verifierBytes   = Encoding.ASCII.GetBytes(codeVerifier);
        var challengeBytes  = SHA256.HashData(verifierBytes);
        var computedChallenge = Base64UrlEncode(challengeBytes);

        // Constant-time comparison — prevents timing oracle attacks
        var computed = Encoding.ASCII.GetBytes(computedChallenge);
        var stored   = Encoding.ASCII.GetBytes(storedChallenge);

        return CryptographicOperations.FixedTimeEquals(computed, stored);
    }

    public bool IsValidChallenge(string codeChallenge)
    {
        if (string.IsNullOrEmpty(codeChallenge))
            return false;

        if (codeChallenge.Length != ExpectedChallengeLength)
            return false;

        return ChallengeRegex.IsMatch(codeChallenge);
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
