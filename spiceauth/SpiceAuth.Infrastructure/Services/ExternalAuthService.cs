using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.DTOs.Auth;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Infrastructure.Services;

public class ExternalAuthService(
    DbContext context,
    UserManager<ApplicationUser> userManager,
    ITokenService tokenService,
    IConfiguration configuration,
    ILogger<ExternalAuthService> logger) : IExternalAuthService
{
    public async Task<ExternalAuthResult> AuthenticateExternalAsync(
        string provider,
        string providerUserId,
        string? email,
        string? username,
        string? avatarUrl)
    {
        var existing = await context.Set<ExternalIdentity>()
            .FirstOrDefaultAsync(e =>
                e.Provider == provider &&
                e.ProviderUserId == providerUserId);

        if (existing != null)
        {
            var knownUser = await userManager.FindByIdAsync(existing.ApplicationUserId.ToString());
            if (knownUser == null)
                return new ExternalAuthResult(false, null, null, "Konto użytkownika nie istnieje", null);

            await UpdateLastLoginAsync(knownUser);
            logger.LogInformation("External login: known user {UserId} via {Provider}", knownUser.Id, provider);
            return await IssueTokensAsync(knownUser);
        }

        if (!string.IsNullOrEmpty(email))
        {
            var localUser = await userManager.FindByEmailAsync(email);
            if (localUser != null)
            {
                await CreateExternalIdentityAsync(localUser.Id, provider, providerUserId, username, email);
                await UpdateLastLoginAsync(localUser);
                logger.LogInformation(
                    "External login: linked existing account {UserId} with {Provider}",
                    localUser.Id, provider);
                return await IssueTokensAsync(localUser);
            }
        }

        var newUser = new ApplicationUser
        {
            Id                = Guid.NewGuid(),
            Email             = email?.ToLower() ?? $"{provider}_{providerUserId}@external.local",
            UserName          = username ?? $"{provider}_{providerUserId}",
            EmailConfirmed    = !string.IsNullOrEmpty(email),
            IsActive          = true,
            ProfilePictureUrl = avatarUrl,
            CreatedAt         = DateTime.UtcNow,
            SecurityStamp     = Guid.NewGuid().ToString()
        };

        var result = await userManager.CreateAsync(newUser);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            logger.LogError("Failed to create external user: {Errors}", errors);
            return new ExternalAuthResult(false, null, null, $"Błąd tworzenia konta: {errors}", null);
        }

        await userManager.AddToRoleAsync(newUser, "User");
        await CreateExternalIdentityAsync(newUser.Id, provider, providerUserId, username, email);

        logger.LogInformation("External login: new user {UserId} created via {Provider}", newUser.Id, provider);
        return await IssueTokensAsync(newUser);
    }

    public async Task<bool> LinkExternalProviderAsync(
        Guid userId,
        string provider,
        string providerUserId,
        string? username = null,
        string? email = null)
    {
        var alreadyLinked = await context.Set<ExternalIdentity>()
            .AnyAsync(e => e.Provider == provider && e.ProviderUserId == providerUserId);

        if (alreadyLinked)
        {
            logger.LogWarning(
                "ProviderUserId {ProviderUserId} for {Provider} already linked to another account",
                providerUserId, provider);
            return false;
        }

        var existingLink = await context.Set<ExternalIdentity>()
            .AnyAsync(e => e.ApplicationUserId == userId && e.Provider == provider);

        if (existingLink)
        {
            logger.LogWarning("User {UserId} already has {Provider} linked", userId, provider);
            return false;
        }

        await CreateExternalIdentityAsync(userId, provider, providerUserId, username, email);
        logger.LogInformation("Linked {Provider} to user {UserId}", provider, userId);
        return true;
    }

    public async Task<bool> UnlinkExternalProviderAsync(Guid userId, string provider)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user == null) return false;

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            var providerCount = await context.Set<ExternalIdentity>()
                .CountAsync(e => e.ApplicationUserId == userId);

            if (providerCount <= 1)
            {
                logger.LogWarning(
                    "Cannot unlink {Provider} from {UserId} — no password and no other providers",
                    provider, userId);
                return false;
            }
        }

        var identity = await context.Set<ExternalIdentity>()
            .FirstOrDefaultAsync(e => e.ApplicationUserId == userId && e.Provider == provider);

        if (identity == null) return false;

        context.Set<ExternalIdentity>().Remove(identity);
        await context.SaveChangesAsync();

        logger.LogInformation("Unlinked {Provider} from user {UserId}", provider, userId);
        return true;
    }

    public async Task<List<LinkedProviderDto>> GetLinkedProvidersAsync(Guid userId)
        => await context.Set<ExternalIdentity>()
            .Where(e => e.ApplicationUserId == userId)
            .Select(e => new LinkedProviderDto(
                e.Provider,
                e.ProviderUserId,
                e.ProviderUsername,
                e.ProviderEmail,
                e.LinkedAt))
            .ToListAsync();

    // ── HELPERS ───────────────────────────────────────────────

    private async Task<ExternalAuthResult> IssueTokensAsync(ApplicationUser user)
    {
        var roles    = await userManager.GetRolesAsync(user);
        var clientId = configuration["Auth:InternalClientId"] ?? "spiceapi-internal";
        var client   = await context.Set<OAuthClient>()
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsActive);

        if (client == null)
        {
            logger.LogError("Internal OAuth client '{ClientId}' not found", clientId);
            return new ExternalAuthResult(false, null, null, "Błąd konfiguracji serwera", null);
        }

        var tokenRequest = new TokenRequest
        {
            UserId   = user.Id,
            ClientId = client.Id,
            Scope    = "openid profile email",
            Roles    = roles.ToList()
        };

        var accessToken  = await tokenService.GenerateAccessTokenAsync(tokenRequest);
        var refreshToken = await tokenService.GenerateRefreshTokenAsync(
            user.Id, client.Id, "openid profile email");

        return new ExternalAuthResult(
            Success:      true,
            AccessToken:  accessToken,
            RefreshToken: refreshToken,
            Message:      "Zalogowano pomyślnie",
            User: new UserDto
            {
                Id        = user.Id,
                Email     = user.Email ?? string.Empty,
                Username  = user.UserName ?? string.Empty,
                FirstName = user.FirstName,
                LastName  = user.LastName,
                IsActive  = user.IsActive,
                CreatedAt = user.CreatedAt
            });
    }

    private async Task CreateExternalIdentityAsync(
        Guid userId,
        string provider,
        string providerUserId,
        string? username,
        string? email)
    {
        var identity = new ExternalIdentity
        {
            UserId            = userId,
            ApplicationUserId = userId,
            Provider          = provider,
            ProviderUserId    = providerUserId,
            ProviderUsername  = username,
            ProviderEmail     = email,
            LinkedAt          = DateTime.UtcNow
        };

        context.Set<ExternalIdentity>().Add(identity);
        await context.SaveChangesAsync();
    }

    private async Task UpdateLastLoginAsync(ApplicationUser user)
    {
        user.LastLoginAt = DateTime.UtcNow;
        await userManager.UpdateAsync(user);
    }
}
