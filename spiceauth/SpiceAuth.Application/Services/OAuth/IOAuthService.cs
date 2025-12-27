using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Core.Entities.OAuth;
using OAuthTokenResponse = SpiceAuth.Application.DTOs.OAuth.TokenResponse;

namespace SpiceAuth.Application.Services.OAuth;

public interface IOAuthService
{
    // Authorization Code Flow
    Task<string> CreateAuthorizationCodeAsync(
        Guid userId,
        Guid clientId,
        string redirectUri,
        string scope,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? nonce);
    
    Task<AuthorizationCode?> ValidateAuthorizationCodeAsync(
        string code,
        Guid clientId,
        string redirectUri,
        string? codeVerifier);
    
    // Token Exchange
    Task<OAuthTokenResponse> ExchangeCodeForTokensAsync(
        string code,
        Guid clientId,
        string redirectUri,
        string? codeVerifier,
        string? clientSecret);
    
    Task<OAuthTokenResponse> RefreshTokenAsync(
        string refreshToken,
        Guid clientId,
        string? clientSecret);
    
    // Client Management
    Task<OAuthClient> RegisterClientAsync(ClientRegistrationRequest request, Guid createdByUserId);
    Task<OAuthClient?> GetClientByIdAsync(Guid clientId);
    Task<OAuthClient?> GetClientByClientIdAsync(string clientId);
    Task<bool> ValidateClientAsync(string clientId, string? clientSecret);
    
    // Consent
    Task<bool> HasConsentAsync(Guid userId, Guid clientId, string scope);
    Task GrantConsentAsync(Guid userId, Guid clientId, string scope);
    Task RevokeConsentAsync(Guid userId, Guid clientId);
    
    // Token Revocation
    Task<bool> RevokeTokenAsync(string token, Guid clientId);
}