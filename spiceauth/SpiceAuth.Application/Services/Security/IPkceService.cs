namespace SpiceAuth.Application.Services.Security;

/// <summary>
/// RFC 7636 — Proof Key for Code Exchange (PKCE) validator.
/// Only S256 is accepted. plain is never permitted.
/// </summary>
public interface IPkceService
{
    /// <summary>
    /// Validates the code_verifier format (length 43–128, unreserved ASCII chars).
    /// Throws <see cref="PkceException"/> on failure.
    /// </summary>
    void ValidateVerifierFormat(string codeVerifier);

    /// <summary>
    /// Derives S256 challenge from verifier and compares in constant time.
    /// Returns true only when the verifier correctly unlocks the stored challenge.
    /// </summary>
    bool VerifyChallenge(string codeVerifier, string storedChallenge);

    /// <summary>
    /// Validates that a submitted code_challenge is syntactically valid base64url (43 chars).
    /// </summary>
    bool IsValidChallenge(string codeChallenge);
}
