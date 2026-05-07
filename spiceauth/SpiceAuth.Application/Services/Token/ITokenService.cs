using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Services.Token;

public interface ITokenService
{
    Task<string> GenerateAccessTokenAsync(TokenRequest request);
    Task<string> GenerateRefreshTokenAsync(Guid userId, Guid clientId, string scope, Guid? organizationId = null);
    Task<string> GenerateIdTokenAsync(Guid userId, Guid clientId, string nonce, string[]? audiences = null);

    /// <summary>
    /// Generates an OIDC Back-Channel Logout Token (logout+jwt).
    /// Signed with the same RSA keypair as id_tokens.
    /// Claims: iss, aud, iat, jti, sid, events.
    /// Short-lived (2 min). Replay-safe via jti.
    /// </summary>
    Task<string> GenerateLogoutTokenAsync(string sid, string audience);

    Task<TokenPayload?> ValidateTokenAsync(string token);
    Task<JwksResponse> GetJwksAsync();
    Task<SigningKey> GetActiveSigningKeyAsync();
    Task RotateKeysAsync();
}