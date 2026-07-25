using SpiceAuth.Application.DTOs.Auth;

namespace SpiceAuth.Application.Services.Identity;

public interface IExternalAuthService
{
    Task<ExternalAuthResult> AuthenticateExternalAsync(
        string provider,
        string providerUserId,
        string? email,
        string? username,
        string? avatarUrl,
        bool emailVerified = false,
        Guid? authenticatedUserId = null);

    Task<bool> LinkExternalProviderAsync(
        Guid userId,
        string provider,
        string providerUserId,
        string? username = null,
        string? email = null,
        string? avatarUrl = null);

    Task<bool> UnlinkExternalProviderAsync(Guid userId, string provider);

    Task<List<LinkedProviderDto>> GetLinkedProvidersAsync(Guid userId);
}

public record ExternalAuthResult(
    bool Success,
    string? AccessToken,
    string? RefreshToken,
    string? Message,
    UserDto? User,
    string? ErrorCode = null,
    bool WasLinked = false);

public record LinkedProviderDto(
    string Provider,
    string ProviderUserId,
    string? ProviderUsername,
    string? ProviderEmail,
    DateTime LinkedAt,
    string? AvatarUrl = null);
