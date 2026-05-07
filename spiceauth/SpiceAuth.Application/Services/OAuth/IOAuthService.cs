using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Application.Services.OAuth;

public interface IOAuthService
{
    // ─────────────────────────────────────────────
    // AUTHORIZATION ENDPOINT (RFC 6749 / OIDC)
    // ─────────────────────────────────────────────
    Task<AuthorizationCode> CreateAuthorizationCodeAsync(
        Guid userId,
        Guid clientId,
        string redirectUri,
        string scope,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? nonce);

    Task<AuthorizationCode?> GetAuthorizationCodeAsync(string code);
    Task<bool> ValidateAuthorizationCodeAsync(string code, Guid clientId, string redirectUri);
    Task MarkAuthorizationCodeAsUsedAsync(string code);

    // ─────────────────────────────────────────────
    // TOKEN ENDPOINT (RFC 6749)
    // ─────────────────────────────────────────────
    Task<TokenResponse> ExchangeAuthorizationCodeAsync(
        string code,
        Guid clientId,
        string redirectUri,
        string? codeVerifier);

    Task<TokenResponse> RefreshTokenAsync(string refreshToken, Guid clientId);

    Task<TokenResponse> ClientCredentialsAsync(string clientId, string clientSecret);

    // ─────────────────────────────────────────────
    // OPENID CONNECT
    // ─────────────────────────────────────────────
    Task<object> GetUserInfoAsync(Guid userId);

    // ─────────────────────────────────────────────
    // TOKEN INTROSPECTION (RFC 7662)
    // ─────────────────────────────────────────────
    Task<object> IntrospectTokenAsync(
        string token,
        string? tokenTypeHint,
        string? clientId,
        string? clientSecret);

    // ─────────────────────────────────────────────
    // TOKEN REVOCATION (RFC 7009)
    // ─────────────────────────────────────────────
    Task RevokeTokenAsync(
        string token,
        string? tokenTypeHint,
        string? clientId,
        string? clientSecret);
    
    // ─────────────────────────────────────────────
    // CLIENT MANAGEMENT
    // ─────────────────────────────────────────────
    Task<OAuthClient?> GetClientByIdAsync(Guid clientId);
    Task<OAuthClient?> GetClientByClientIdAsync(string clientId);
    Task<bool> ValidateClientAsync(string clientId, string? clientSecret = null);
    Task ValidateClientCredentialsAsync(string clientId, string? clientSecret);
    Task<bool> ValidateRedirectUriAsync(Guid clientId, string redirectUri);

    // ─────────────────────────────────────────────
    // CONSENT (OIDC)
    // ─────────────────────────────────────────────
    Task<bool> HasUserConsentedAsync(Guid userId, Guid clientId, string scope);
    Task GrantConsentAsync(Guid userId, Guid clientId, string scope);
    Task RevokeConsentAsync(Guid userId, Guid clientId);

    // ─────────────────────────────────────────────
    // DYNAMIC CLIENT REGISTRATION
    // ─────────────────────────────────────────────
    Task<ClientRegistrationResponse> RegisterClientAsync(RegisterClientRequest request, Guid createdByUserId);
    Task<bool> DeleteClientAsync(Guid clientId, Guid userId);
    Task<List<OAuthClient>> GetUserClientsAsync(Guid userId);
    
    Task<TokenResponse> CreateAccessAndRefreshTokensAsync(Guid userId, string clientId, string scope);
    Task<TokenResponse?> RotateRefreshTokenAsync(string refreshToken, string clientId);
    Task<AuthorizationCode?> ValidateAuthorizationCodeAsync(string code, string clientId, string? codeVerifier);
    Task RevokeRefreshTokenAsync(string tokenHash);
    
    Task<OAuthClient> UpdateClientAsync(Guid clientInternalId, UpdateClientRequest request, Guid updatedByUserId);
    Task<string> RotateClientSecretAsync(Guid clientInternalId, Guid requestedByUserId);
    Task SetClientStatusAsync(Guid clientInternalId, bool isActive, Guid updatedByUserId);

}
