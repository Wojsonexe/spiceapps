using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Services.Token;

public interface ITokenService
{
    Task<string> GenerateAccessTokenAsync(TokenRequest request);
    Task<string> GenerateRefreshTokenAsync(Guid userId, Guid clientId, string scope, Guid? organizationId = null);
    Task<string> GenerateIdTokenAsync(Guid userId, Guid clientId, string nonce, string[]? audiences = null);
    Task<TokenPayload?> ValidateTokenAsync(string token);
    Task<JwksResponse> GetJwksAsync();
    Task<SigningKey> GetActiveSigningKeyAsync();
    Task RotateKeysAsync();
}