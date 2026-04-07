

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Application.Exceptions;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Enums;
using TokenRequest = SpiceAuth.Application.Services.Token.TokenRequest;

namespace SpiceAuth.Application.Services.OAuth;

public  class OAuthService(
    DbContext context,
    IIdentityStore identity,
    ITokenService tokenService,
    ILogger<OAuthService> logger,
    UserManager<ApplicationUser> userManager) : IOAuthService
{
    private readonly DbContext _context = context;
    private readonly IIdentityStore _identity = identity;
    private readonly ITokenService _tokenService = tokenService;
    private readonly ILogger<OAuthService> _logger = logger;
    private readonly UserManager<ApplicationUser> _userManager = userManager;
    

    public Task<TokenResponse> RefreshTokenAsync(string refreshToken, Guid clientId)
        => RefreshInternalAsync(refreshToken, clientId);

    public async Task<object> GetUserInfoAsync(Guid userId)
    {
        var user = await _identity.GetUserAsync(userId);

        if (user == null || !user.IsActive)
            throw new OAuthException("invalid_token");

        return new
        {
            sub = user.Id,
            name = user.UserName,
            email = user.Email,
            email_verified = user.EmailConfirmed,
            given_name = user.FirstName,
            family_name = user.LastName,
            picture = user.ProfilePictureUrl,
            roles = user.UserRoles.Select(ur => ur.Role.Name).ToList()
            
        };
    }


    public async Task ValidateClientCredentialsAsync(string clientId, string? clientSecret)
    {
        var client = await GetClientByClientIdAsync(clientId);

        if (client == null || !client.IsActive)
            throw new OAuthException("invalid_client", "Invalid client");

        if (client.ClientType == ClientType.Confidential)
        {
            if (string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(client.ClientSecretHash))
                throw new OAuthException("invalid_client", "Client secret required");

            if (!VerifyClientSecret(clientSecret, client.ClientSecretHash))
                throw new OAuthException("invalid_client", "Invalid client secret");
        }
    }
    
    public async Task<TokenResponse> ClientCredentialsAsync(string clientId, string clientSecret)
    {
        await ValidateClientAsync(clientId, clientSecret);
        
        var client = await GetClientByClientIdAsync(clientId);
        
        var tokenRequest = new TokenRequest
        {
            ClientId = client!.Id,
            Scope = string.Join(" ", client.AllowedScopes)
        };

        var accessToken = await _tokenService.GenerateAccessTokenAsync(tokenRequest);

        return new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = client.AccessTokenLifetime,
            Scope = tokenRequest.Scope
        };
    }

    public async Task<AuthorizationCode> CreateAuthorizationCodeAsync(
        Guid userId,
        Guid clientId,
        string redirectUri,
        string scope,
        string? codeChallenge = null,
        string? codeChallengeMethod = null,
        string? nonce = null)
    {
        var code = GenerateSecureCode();
        
        var authCode = new AuthorizationCode
        {
            Id = Guid.NewGuid(),
            Code = code,
            ClientId = clientId,
            UserId = userId,
            RedirectUri = redirectUri,
            Scope = scope,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            Nonce = nonce,
            IsUsed = false,
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            CreatedAt = DateTime.UtcNow
        };

        _context.Set<AuthorizationCode>().Add(authCode);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Created authorization code for user {UserId}, client {ClientId}",
            userId, clientId);

        return authCode;
    }

    public async Task<AuthorizationCode?> GetAuthorizationCodeAsync(string code)
    {
        return await _context.Set<AuthorizationCode>()
            .FirstOrDefaultAsync(ac => ac.Code == code);
    }

    public async Task<TokenResponse> CreateAccessAndRefreshTokensAsync(Guid userId, string clientId, string scope)
    {
        var client = await GetClientByClientIdAsync(clientId);
        if (client == null)
        {
            throw new InvalidOperationException("Client not found");
        }
        
        var redirectUris = System.Text.Json.JsonSerializer.Deserialize<List<string>>(client.RedirectUris) ?? new List<string>();
        var redirectUri = redirectUris.FirstOrDefault() ?? "http://localhost";

        var authCode = await CreateAuthorizationCodeAsync(userId, client.Id, redirectUri, scope);
        return await ExchangeAuthorizationCodeAsync(authCode.Code, client.Id, redirectUri, null);
    }
    
    public async Task<TokenResponse?> RotateRefreshTokenAsync(string refreshToken, string clientId)
    {
        try 
        {
            var client = await GetClientByClientIdAsync(clientId);
            if (client == null) return null;
        
            return await RefreshTokenAsync(refreshToken, client.Id);
        }
        catch 
        {
            return null;
        }
    }
    
    public async Task<AuthorizationCode?> ValidateAuthorizationCodeAsync(string code, string clientId, string? codeVerifier)
    {
        var client = await GetClientByClientIdAsync(clientId);
        if (client == null) return null;

        var authCode = await GetAuthorizationCodeAsync(code);
        if (authCode == null || authCode.ClientId != client.Id) return null;

        if (!string.IsNullOrEmpty(authCode.CodeChallenge) && !string.IsNullOrEmpty(codeVerifier))
        {
            if (!ValidatePkce(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod))
                return null;
        }

        return authCode;
    }

    public async Task RevokeRefreshTokenAsync(string tokenHash)
    {
        var refreshToken = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash);
    
        if (refreshToken != null)
        {
            refreshToken.IsRevoked = true;
            await _context.SaveChangesAsync();
            _logger.LogInformation("Revoked refresh token: {TokenHash}", tokenHash);
        }
    }

    public async Task<bool> ValidateAuthorizationCodeAsync(string code, Guid clientId, string redirectUri)
    {
        var authCode = await GetAuthorizationCodeAsync(code);

        if (authCode == null)
        {
            _logger.LogWarning("Authorization code not found: {Code}", code);
            return false;
        }

        if (authCode.IsUsed)
        {
            _logger.LogWarning("Authorization code already used: {Code}", code);
            return false;
        }

        if (authCode.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Authorization code expired: {Code}", code);
            return false;
        }

        if (authCode.ClientId != clientId)
        {
            _logger.LogWarning("Client ID mismatch for authorization code: {Code}", code);
            return false;
        }

        if (authCode.RedirectUri != redirectUri)
        {
            _logger.LogWarning("Redirect URI mismatch for authorization code: {Code}", code);
            return false;
        }

        return true;
    }

    public async Task MarkAuthorizationCodeAsUsedAsync(string code)
    {
        var authCode = await GetAuthorizationCodeAsync(code);
        if (authCode != null)
        {
            authCode.IsUsed = true;
            await _context.SaveChangesAsync();
        }
    }

    public async Task<TokenResponse> ExchangeAuthorizationCodeAsync(
        string code,
        Guid clientId,
        string redirectUri,
        string? codeVerifier)
    {
        var authCode = await _context.Set<AuthorizationCode>()
            .FirstOrDefaultAsync(c => c.Code == code && !c.IsUsed);

        if (authCode == null || authCode.ExpiresAt < DateTime.UtcNow)
            throw new InvalidOperationException("Authorization code is invalid or expired");

        if (authCode.ClientId != clientId)
            throw new InvalidOperationException("Client mismatch");

        if (!string.IsNullOrEmpty(authCode.RedirectUri) &&
            authCode.RedirectUri != redirectUri)
            throw new InvalidOperationException("redirect_uri mismatch");

        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
                throw new InvalidOperationException("code_verifier is required");

            using var sha256  = SHA256.Create();
            var verifierBytes = Encoding.ASCII.GetBytes(codeVerifier);
            var challengeBytes = sha256.ComputeHash(verifierBytes);
            var computedChallenge = Base64UrlEncoder.Encode(challengeBytes);

        if (computedChallenge != authCode.CodeChallenge)
                throw new InvalidOperationException("code_verifier does not match code_challenge");
        }

        authCode.IsUsed  = true;
        authCode.UsedAt  = DateTime.UtcNow;

        var user = await _userManager.FindByIdAsync(authCode.UserId.ToString())
            ?? throw new InvalidOperationException("User not found");

        var userRoles = await _userManager.GetRolesAsync(user);

        var audience = ResolveAudience(authCode.Scope);

        var tokenRequest = new TokenRequest
        {
            UserId   = authCode.UserId,
            ClientId = clientId,
            Scope    = authCode.Scope ?? "openid profile",
            Roles    = userRoles.ToList(),
            Nonce    = authCode.Nonce,
            Audience = audience  
        };

        var accessToken  = await _tokenService.GenerateAccessTokenAsync(tokenRequest);
        var refreshToken = await _tokenService.GenerateRefreshTokenAsync(
            authCode.UserId, clientId, authCode.Scope ?? "openid profile");

        string? idToken = null;
        if (!string.IsNullOrEmpty(authCode.Nonce) && (authCode.Scope?.Contains("openid") ?? false))
        {
            idToken = await _tokenService.GenerateIdTokenAsync(
                authCode.UserId, clientId,
                authCode.Nonce, [clientId.ToString()]);
        }

        await _context.SaveChangesAsync();

        return new TokenResponse
        {
            AccessToken  = accessToken,
            RefreshToken = refreshToken,
            IdToken      = idToken,
            TokenType    = "Bearer",
            ExpiresIn    = 900,
            Scope        = authCode.Scope
        };
    }
    
    private async Task<TokenResponse> RefreshInternalAsync(string refreshToken, Guid clientId)
    {
        var tokenHash = HashToken(refreshToken);
        
        var storedToken = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(rt => rt.TokenHash == tokenHash && rt.ClientId == clientId);

        if (storedToken == null)
        {
            throw new InvalidOperationException("Invalid refresh token");
        }

        if (storedToken.IsRevoked)
        {
            _logger.LogWarning("Revoked refresh token used: {TokenId}", storedToken.Id);
            throw new InvalidOperationException("Token has been revoked");
        }

        if (storedToken.IsUsed)
        {
            _logger.LogWarning("Refresh token reuse detected: {TokenId}", storedToken.Id);
            // Revoke entire token family
            await RevokeTokenFamilyAsync(storedToken.Id);
            throw new InvalidOperationException("Token reuse detected - all tokens revoked");
        }

        if (storedToken.ExpiresAt < DateTime.UtcNow)
        {
            throw new InvalidOperationException("Refresh token expired");
        }

        storedToken.IsUsed = true;

        var roles = await _context.Set<Core.Entities.Authorization.UserRole>()
            .Where(ur => ur.UserId == storedToken.UserId)
            .Include(ur => ur.Role)
            .Select(ur => ur.Role.Name)
            .ToListAsync();

        var tokenRequest = new TokenRequest
        {
            UserId = storedToken.UserId,
            ClientId = storedToken.ClientId,
            Scope = storedToken.Scope,
            Roles = roles,
            OrganizationId = storedToken.OrganizationId
        };

        var newAccessToken = await _tokenService.GenerateAccessTokenAsync(tokenRequest);
        var newRefreshToken = await _tokenService.GenerateRefreshTokenAsync(
            storedToken.UserId,
            storedToken.ClientId,
            storedToken.Scope,
            storedToken.OrganizationId);

        // Link new token to parent (for token family tracking)
        var newToken = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(rt => rt.TokenHash == HashToken(newRefreshToken));
        
        if (newToken != null)
        {
            newToken.ParentTokenId = storedToken.Id;
        }

        await _context.SaveChangesAsync();

        _logger.LogInformation("Refreshed access token for user {UserId}", storedToken.UserId);

        return new TokenResponse
        {
            AccessToken = newAccessToken,
            TokenType = "Bearer",
            ExpiresIn = 900,
            RefreshToken = newRefreshToken,
            Scope = storedToken.Scope
        };
    }

    public async Task<OAuthClient?> GetClientByIdAsync(Guid clientId)
    {
        return await _context.Set<OAuthClient>()
            .FirstOrDefaultAsync(c => c.Id == clientId);
    }

    public async Task<OAuthClient?> GetClientByClientIdAsync(string clientId)
    {
        return await _context.Set<OAuthClient>()
            .FirstOrDefaultAsync(c => c.ClientId == clientId);
    }

    public async Task<bool> ValidateClientAsync(string clientId, string? clientSecret = null)
    {
        var client = await GetClientByClientIdAsync(clientId);

        if (client == null || !client.IsActive)
        {
            return false;
        }

        if (!string.IsNullOrEmpty(clientSecret))
        {
            if (string.IsNullOrEmpty(client.ClientSecretHash))
            {
                return false;
            }

            return VerifyClientSecret(clientSecret, client.ClientSecretHash);
        }

        return true;
    }

    public async Task<bool> ValidateRedirectUriAsync(Guid clientId, string redirectUri)
    {
        var client = await GetClientByIdAsync(clientId);
        
        if (client == null)
            return false;

        var allowedUris = System.Text.Json.JsonSerializer.Deserialize<List<string>>(client.RedirectUris);
        return allowedUris?.Contains(redirectUri) ?? false;
    }

    public async Task<bool> HasUserConsentedAsync(Guid userId, Guid clientId, string scope)
    {
        var consent = await _context.Set<ConsentGrant>()
            .FirstOrDefaultAsync(c => 
                c.UserId == userId && 
                c.ClientId == clientId && 
                !c.IsRevoked);

        if (consent == null)
            return false;

        // Check if all requested scopes are in granted scopes
        var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var grantedScopes = consent.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        return requestedScopes.All(s => grantedScopes.Contains(s));
    }

    public async Task GrantConsentAsync(Guid userId, Guid clientId, string scope)
    {
        var existingConsent = await _context.Set<ConsentGrant>()
            .FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId);

        if (existingConsent != null)
        {
            existingConsent.Scope = scope;
            existingConsent.GrantedAt = DateTime.UtcNow;
            existingConsent.IsRevoked = false;
        }
        else
        {
            var consent = new ConsentGrant
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                ClientId = clientId,
                Scope = scope,
                GrantedAt = DateTime.UtcNow,
                IsRevoked = false,
                CreatedAt = DateTime.UtcNow
            };

            _context.Set<ConsentGrant>().Add(consent);
        }

        await _context.SaveChangesAsync();

        _logger.LogInformation("User {UserId} granted consent to client {ClientId}", userId, clientId);
    }

    public async Task RevokeConsentAsync(Guid userId, Guid clientId)
    {
        var consent = await _context.Set<ConsentGrant>()
            .FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId);

        if (consent != null)
        {
            consent.IsRevoked = true;
            await _context.SaveChangesAsync();

            _logger.LogInformation("Revoked consent for user {UserId}, client {ClientId}", userId, clientId);
        }
    }

    public async Task RevokeTokenAsync(
        string token,
        string? tokenTypeHint,
        string? clientId,
        string? clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            throw new OAuthException("invalid_client");

        if (!await ValidateClientAsync(clientId, clientSecret))
            throw new OAuthException("invalid_client");

        var hash = HashToken(token);

        var refresh = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(t => t.TokenHash == hash);

        if (refresh != null)
        {
            refresh.IsRevoked = true;
            await _context.SaveChangesAsync();
        }
    }

    public async Task<object> IntrospectTokenAsync(
        string token,
        string? tokenTypeHint,
        string? clientId,
        string? clientSecret)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            throw new OAuthException("invalid_client");

        if (!await ValidateClientAsync(clientId, clientSecret))
            throw new OAuthException("invalid_client");

        var hash = HashToken(token);

        var refresh = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(t => t.TokenHash == hash);

        if (refresh == null || refresh.IsRevoked || refresh.ExpiresAt < DateTime.UtcNow)
            return new { active = false };
        
        return new
        {
            active = true,
            sub = refresh.UserId,
            client_id = refresh.ClientId,
            scope = refresh.Scope,
            exp = new DateTimeOffset(refresh.ExpiresAt).ToUnixTimeSeconds()
        };
    }

    public async Task<ClientRegistrationResponse> RegisterClientAsync(
        RegisterClientRequest request, Guid createdByUserId)
    {
        // Generate client credentials
        var clientId = Guid.NewGuid().ToString("N");
        var clientSecret = GenerateClientSecret();
        var clientSecretHash = HashClientSecret(clientSecret);

        // Parse client type
        if (!Enum.TryParse<ClientType>(request.ClientType, true, out var clientType))
            clientType = ClientType.Confidential;

        var client = new OAuthClient
        {
            Id = Guid.NewGuid(),
            ClientId = clientId,
            ClientSecretHash = clientType == ClientType.Public ? null : clientSecretHash,
            Name = request.Name,                  
            Description = request.Description,
            ClientType = clientType,
            RedirectUris = System.Text.Json.JsonSerializer.Serialize(request.RedirectUris),
            PostLogoutRedirectUris = System.Text.Json.JsonSerializer.Serialize(
                request.PostLogoutRedirectUris ?? []),
            AllowedScopes = System.Text.Json.JsonSerializer.Serialize(
                request.AllowedScopes),           
            AllowedGrantTypes = System.Text.Json.JsonSerializer.Serialize(
                new[] { "authorization_code", "refresh_token" }),
            RequireConsent = request.RequireConsent, 
            RequirePkce = request.RequirePkce,
            AccessTokenLifetime = 900,
            RefreshTokenLifetime = 604800,
            IsActive = true,
            CreatedByUserId = createdByUserId,
            CreatedAt = DateTime.UtcNow
        };

        _context.Set<OAuthClient>().Add(client);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Registered new OAuth client: {ClientId}", clientId);

        return new ClientRegistrationResponse
        {
            ClientId = clientId,
            ClientSecret = clientType == ClientType.Public ? null! : clientSecret,
            ClientName = client.Name,
            RedirectUris = request.RedirectUris,
            AllowedScopes = request.AllowedScopes,
            RequiresPkce = client.RequirePkce,
            AccessTokenLifetime = client.AccessTokenLifetime,
            RefreshTokenLifetime = client.RefreshTokenLifetime,
            CreatedAt = client.CreatedAt
        };
    }

    public async Task<bool> DeleteClientAsync(Guid clientId, Guid userId)
    {
        var client = await GetClientByIdAsync(clientId);
        
        if (client == null || client.CreatedByUserId != userId)
        {
            return false;
        }

        client.IsActive = false;
        await _context.SaveChangesAsync();

        _logger.LogInformation("Deactivated OAuth client: {ClientId}", client.ClientId);
        return true;
    }

    public async Task<List<OAuthClient>> GetUserClientsAsync(Guid userId)
    {
        return await _context.Set<OAuthClient>()
            .Where(c => c.CreatedByUserId == userId)
            .OrderByDescending(c => c.CreatedAt)
            .ToListAsync();
    }

    private static string GenerateClientSecret()
    {
        var bytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }

        return Convert.ToBase64String(bytes);
    }

    private async Task RevokeTokenFamilyAsync(Guid tokenId)
    {
        // Revoke all tokens in the family (parent and children)
        var tokens = await _context.Set<RefreshToken>()
            .Where(rt => rt.Id == tokenId || rt.ParentTokenId == tokenId)
            .ToListAsync();

        foreach (var token in tokens)
        {
            token.IsRevoked = true;
        }

        await _context.SaveChangesAsync();

        _logger.LogWarning("Revoked token family, {Count} tokens affected", tokens.Count);
    }

    private static string GenerateSecureCode()
    {
        var bytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    private static string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hash);
    }

    private static string HashClientSecret(string secret)
    {
        // Use BCrypt with work factor 12 (secure and reasonable performance)
        return BCrypt.Net.BCrypt.HashPassword(secret, workFactor: 12);
    }
    
    private static bool VerifyClientSecret(string secret, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(secret, hash);
        }
        catch
        {
            return false;
        }
    }


    private static bool ValidatePkce(string codeVerifier, string codeChallenge, string? method)
    {
        if (method != "S256")
        {
            return false;
        }

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
        var computedChallenge = Convert.ToBase64String(hash)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");

        return computedChallenge == codeChallenge;
    }
    
    public async Task<OAuthClient> UpdateClientAsync(
        Guid clientInternalId, UpdateClientRequest request, Guid updatedByUserId)
    {
        var client = await GetClientByIdAsync(clientInternalId)
            ?? throw new InvalidOperationException("Client not found");

        client.Name = request.Name;
        client.Description = request.Description;
        client.RedirectUris = System.Text.Json.JsonSerializer.Serialize(request.RedirectUris);
        client.PostLogoutRedirectUris = System.Text.Json.JsonSerializer.Serialize(
            request.PostLogoutRedirectUris ?? []);
        client.AllowedScopes = System.Text.Json.JsonSerializer.Serialize(request.AllowedScopes);
        client.RequireConsent = request.RequireConsent;
        client.RequirePkce = request.RequirePkce;
        client.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Updated OAuth client: {ClientId}, by user {UserId}",
            client.ClientId, updatedByUserId);

        return client;
    }

    public async Task<string> RotateClientSecretAsync(Guid clientInternalId, Guid requestedByUserId)
    {
        var client = await GetClientByIdAsync(clientInternalId)
            ?? throw new InvalidOperationException("Client not found");

        if (client.ClientType == ClientType.Public)
            throw new InvalidOperationException("Public clients do not use client secrets");

        var newSecret = GenerateClientSecret();
        client.ClientSecretHash = HashClientSecret(newSecret);
        client.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Rotated client secret: {ClientId}, by user {UserId}",
            client.ClientId, requestedByUserId);

        return newSecret;
    }

    public async Task SetClientStatusAsync(Guid clientInternalId, bool isActive, Guid updatedByUserId)
    {
        var client = await GetClientByIdAsync(clientInternalId)
            ?? throw new InvalidOperationException("Client not found");

        client.IsActive = isActive;
        client.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Client {ClientId} status set to {Status} by user {UserId}",
            client.ClientId, isActive ? "Active" : "Inactive", updatedByUserId);
    }
    
    private static string ResolveAudience(string? scope)
    {
        if (string.IsNullOrEmpty(scope)) return "spiceapi";

        if (scope.Split(' ').Any(s =>
                s == "spiceapi" || s.StartsWith("spiceapi:")))
            return "spiceapi";

        return "spiceauth";
    }
}