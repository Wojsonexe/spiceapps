namespace SpiceAuth.Application.Exceptions;

/// <summary>
/// Thrown when an authorization code is presented more than once.
/// Signals a replay attack — all tokens issued for the affected user/client should be revoked.
/// </summary>
public sealed class AuthorizationCodeReplayException(string codePrefix)
    : Exception($"Authorization code replay detected (code prefix: {codePrefix})")
{
    public string CodePrefix { get; } = codePrefix;
}
