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
        string? avatarUrl,
        bool emailVerified = false,
        Guid? authenticatedUserId = null)
    {
        // Case 3a: known ExternalIdentity → log in as the linked user
        var existing = await context.Set<ExternalIdentity>()
            .FirstOrDefaultAsync(e =>
                e.Provider == provider &&
                e.ProviderUserId == providerUserId);

        if (existing != null)
        {
            var knownUser = await userManager.FindByIdAsync(existing.UserId.ToString());
            if (knownUser == null)
                return new ExternalAuthResult(false, null, null, "Konto użytkownika nie istnieje", null);

            await UpdateLastLoginAsync(knownUser);
            logger.LogInformation("External login: known user {UserId} via {Provider}", knownUser.Id, provider);
            return await IssueTokensAsync(knownUser);
        }

        // Case 3b: no ExternalIdentity, but caller has an active session → link
        if (authenticatedUserId.HasValue)
        {
            var sessionUser = await userManager.FindByIdAsync(authenticatedUserId.Value.ToString());
            if (sessionUser == null)
                return new ExternalAuthResult(false, null, null, "Użytkownik sesji nie istnieje", null);

            var alreadyHasProvider = await context.Set<ExternalIdentity>()
                .AnyAsync(e => e.UserId == authenticatedUserId.Value && e.Provider == provider);

            if (alreadyHasProvider)
            {
                logger.LogWarning("User {UserId} already has {Provider} linked", authenticatedUserId, provider);
                return new ExternalAuthResult(false, null, null,
                    "Discord już jest połączony z tym kontem", null, "already_linked");
            }

            await CreateExternalIdentityAsync(sessionUser.Id, provider, providerUserId, username, email, avatarUrl);
            await UpdateLastLoginAsync(sessionUser);
            logger.LogInformation("External link (session): linked {Provider} to user {UserId}", provider, sessionUser.Id);
            var linkTokens = await IssueTokensAsync(sessionUser);
            return linkTokens with { WasLinked = true };
        }

        // Case 3c: no ExternalIdentity, no session
        // Email verified and matches existing account → block to prevent account takeover
        if (emailVerified && !string.IsNullOrEmpty(email))
        {
            var localUser = await userManager.FindByEmailAsync(email);
            if (localUser != null)
            {
                logger.LogWarning(
                    "Email conflict: {Provider} email {Email} matches existing account {UserId} — no active session",
                    provider, email, localUser.Id);
                return new ExternalAuthResult(false, null, null,
                    "Konto z tym adresem email już istnieje. Zaloguj się hasłem aby połączyć konta.",
                    null, "email_conflict");
            }
        }

        // No match → provision new account
        var newUser = new ApplicationUser
        {
            Id                = Guid.NewGuid(),
            Email             = email?.ToLower() ?? $"{provider}_{providerUserId}@external.local",
            UserName          = username ?? $"{provider}_{providerUserId}",
            EmailConfirmed    = emailVerified && !string.IsNullOrEmpty(email),
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
        await CreateExternalIdentityAsync(newUser.Id, provider, providerUserId, username, email, avatarUrl);

        logger.LogInformation("External login: new user {UserId} created via {Provider}", newUser.Id, provider);
        return await IssueTokensAsync(newUser);
    }

    public async Task<bool> LinkExternalProviderAsync(
        Guid userId,
        string provider,
        string providerUserId,
        string? username = null,
        string? email = null,
        string? avatarUrl = null)
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
            .AnyAsync(e => e.UserId == userId && e.Provider == provider);

        if (existingLink)
        {
            logger.LogWarning("User {UserId} already has {Provider} linked", userId, provider);
            return false;
        }

        await CreateExternalIdentityAsync(userId, provider, providerUserId, username, email, avatarUrl);
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
                .CountAsync(e => e.UserId == userId);

            if (providerCount <= 1)
            {
                logger.LogWarning(
                    "Cannot unlink {Provider} from {UserId} — no password and no other providers",
                    provider, userId);
                return false;
            }
        }

        var identity = await context.Set<ExternalIdentity>()
            .FirstOrDefaultAsync(e => e.UserId == userId && e.Provider == provider);

        if (identity == null) return false;

        context.Set<ExternalIdentity>().Remove(identity);
        await context.SaveChangesAsync();

        logger.LogInformation("Unlinked {Provider} from user {UserId}", provider, userId);
        return true;
    }

    public async Task<List<LinkedProviderDto>> GetLinkedProvidersAsync(Guid userId)
        => await context.Set<ExternalIdentity>()
            .Where(e => e.UserId == userId)
            .Select(e => new LinkedProviderDto(
                e.Provider,
                e.ProviderUserId,
                e.ProviderUsername,
                e.ProviderEmail,
                e.LinkedAt,
                e.AvatarUrl))
            .ToListAsync();

    // ── Helpers ───────────────────────────────────────────────────────────────

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
            Roles    = roles.ToArray()
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
        string? email,
        string? avatarUrl = null)
    {
        var identity = new ExternalIdentity
        {
            UserId           = userId,
            Provider         = provider,
            ProviderUserId   = providerUserId,
            ProviderUsername = username,
            ProviderEmail    = email,
            AvatarUrl        = avatarUrl,
            LinkedAt         = DateTime.UtcNow
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
