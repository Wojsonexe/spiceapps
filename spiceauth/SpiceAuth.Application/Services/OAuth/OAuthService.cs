using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.DTOs.OAuth;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.OAuth;
using OAuthTokenResponse = SpiceAuth.Application.DTOs.OAuth.TokenResponse;

namespace SpiceAuth.Application.Services.OAuth;

public class OAuthService(
    DbContext context,
    ITokenService tokenService,
    IPasswordHasher passwordHasher,
    ILogger<OAuthService> logger) : IOAuthService
{
    private readonly DbContext _context = context;
    private readonly ITokenService _tokenService = tokenService;
    private readonly IPasswordHasher _passwordHasher = passwordHasher;
    private readonly ILogger<OAuthService> _logger = logger;

    public async Task<string> CreateAuthorizationCodeAsync(
        Guid userId,
        Guid clientId,
        string redirectUri,
        string scope,
        string? codeChallenge,
        string? codeChallengeMethod,
        string? nonce)
    {
        // Generate secure random code
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
            ExpiresAt = DateTime.UtcNow.AddMinutes(10), // Auth codes expire quickly
            CreatedAt = DateTime.UtcNow
        };

        _context.Set<AuthorizationCode>().Add(authCode);
        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Created authorization code for user {UserId}, client {ClientId}",
            userId, clientId);

        return code;
    }

    public async Task<AuthorizationCode?> ValidateAuthorizationCodeAsync(
        string code,
        Guid clientId,
        string redirectUri,
        string? codeVerifier)
    {
        var authCode = await _context.Set<AuthorizationCode>()
            .FirstOrDefaultAsync(ac => ac.Code == code && ac.ClientId == clientId);

        if (authCode == null)
        {
            _logger.LogWarning("Authorization code not found: {Code}", code);
            return null;
        }

        // Check if already used
        if (authCode.IsUsed)
        {
            _logger.LogWarning("Authorization code already used: {Code}", code);
            return null;
        }

        // Check if expired
        if (authCode.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Authorization code expired: {Code}", code);
            return null;
        }

        // Validate redirect URI
        if (authCode.RedirectUri != redirectUri)
        {
            _logger.LogWarning(
                "Redirect URI mismatch. Expected: {Expected}, Got: {Actual}",
                authCode.RedirectUri, redirectUri);
            return null;
        }

        // Validate PKCE if present
        if (!string.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
            {
                _logger.LogWarning("Code verifier required but not provided");
                return null;
            }

            if (!ValidatePkce(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod))
            {
                _logger.LogWarning("PKCE validation failed");
                return null;
            }
        }

        return authCode;
    }

    public async Task<OAuthTokenResponse> ExchangeCodeForTokensAsync(
        string code,
        Guid clientId,
        string redirectUri,
        string? codeVerifier,
        string? clientSecret)
    {
        var authCode = await ValidateAuthorizationCodeAsync(code, clientId, redirectUri, codeVerifier);

        if (authCode == null)
        {
            throw new InvalidOperationException("Invalid authorization code");
        }

        // Mark code as used
        authCode.IsUsed = true;
        await _context.SaveChangesAsync();

        // Get user roles for token
        var userRoles = await _context.Set<Core.Entities.Authorization.UserRole>()
            .Where(ur => ur.UserId == authCode.UserId)
            .Include(ur => ur.Role)
            .Select(ur => ur.Role.Name)
            .ToListAsync();

        // Generate access token
        var tokenRequest = new Token.TokenRequest
        {
            UserId = authCode.UserId,
            ClientId = clientId,
            Scope = authCode.Scope,
            Roles = userRoles,
            Nonce = authCode.Nonce
        };

        var accessToken = await _tokenService.GenerateAccessTokenAsync(tokenRequest);

        // Generate refresh token if offline_access scope is present
        string? refreshToken = null;
        if (authCode.Scope.Contains("offline_access"))
        {
            refreshToken = await _tokenService.GenerateRefreshTokenAsync(
                authCode.UserId,
                clientId,
                authCode.Scope);
        }

        // Generate ID token if openid scope is present
        string? idToken = null;
        if (authCode.Scope.Contains("openid") && !string.IsNullOrEmpty(authCode.Nonce))
        {
            idToken = await _tokenService.GenerateIdTokenAsync(
                authCode.UserId,
                clientId,
                authCode.Nonce);
        }

        _logger.LogInformation(
            "Exchanged authorization code for tokens. User: {UserId}, Client: {ClientId}",
            authCode.UserId, clientId);

        return new OAuthTokenResponse()
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = 900, // 15 minutes
            RefreshToken = refreshToken,
            IdToken = idToken,
            Scope = authCode.Scope
        };
    }

    public async Task<OAuthTokenResponse> RefreshTokenAsync(
        string refreshToken,
        Guid clientId,
        string? clientSecret)
    {
        var tokenHash = HashToken(refreshToken);

        var storedToken = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(rt => 
                rt.TokenHash == tokenHash && 
                rt.ClientId == clientId &&
                !rt.IsRevoked &&
                !rt.IsUsed);

        if (storedToken == null)
        {
            _logger.LogWarning("Refresh token not found or invalid");
            throw new InvalidOperationException("Invalid refresh token");
        }

        if (storedToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Refresh token expired");
            throw new InvalidOperationException("Refresh token expired");
        }

        // Mark old token as used
        storedToken.IsUsed = true;

        // Get user roles
        var userRoles = await _context.Set<Core.Entities.Authorization.UserRole>()
            .Where(ur => ur.UserId == storedToken.UserId)
            .Include(ur => ur.Role)
            .Select(ur => ur.Role.Name)
            .ToListAsync();

        // Generate new access token
        var tokenRequest = new Token.TokenRequest
        {
            UserId = storedToken.UserId,
            ClientId = clientId,
            Scope = storedToken.Scope,
            Roles = userRoles,
            OrganizationId = storedToken.OrganizationId
        };

        var accessToken = await _tokenService.GenerateAccessTokenAsync(tokenRequest);

        // Generate new refresh token (rotation)
        var newRefreshToken = await _tokenService.GenerateRefreshTokenAsync(
            storedToken.UserId,
            clientId,
            storedToken.Scope,
            storedToken.OrganizationId);

        // Link old token to new (for replay detection)
        var newStoredToken = await _context.Set<RefreshToken>()
            .OrderByDescending(rt => rt.CreatedAt)
            .FirstAsync(rt => rt.UserId == storedToken.UserId && rt.ClientId == clientId);
        
        newStoredToken.ParentTokenId = storedToken.Id;

        await _context.SaveChangesAsync();

        _logger.LogInformation(
            "Refreshed tokens for user {UserId}, client {ClientId}",
            storedToken.UserId, clientId);

        return new OAuthTokenResponse()
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = 900,
            RefreshToken = newRefreshToken,
            Scope = storedToken.Scope
        };
    }

    // Helper methods
    private static string GenerateSecureCode()
    {
        var bytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    private static bool ValidatePkce(string verifier, string challenge, string? method)
    {
        if (method == null || method == "plain")
        {
            return verifier == challenge;
        }

        if (method == "S256")
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(verifier));
            var computedChallenge = Convert.ToBase64String(hash)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
            return computedChallenge == challenge;
        }

        return false;
    }

    private static string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToBase64String(hash);
    }

    // Client management methods - TO BE CONTINUED in next message
    public Task<OAuthClient> RegisterClientAsync(ClientRegistrationRequest request, Guid createdByUserId)
    {
        throw new NotImplementedException();
    }

    public Task<OAuthClient?> GetClientByIdAsync(Guid clientId)
    {
        throw new NotImplementedException();
    }

    public Task<OAuthClient?> GetClientByClientIdAsync(string clientId)
    {
        throw new NotImplementedException();
    }

    public Task<bool> ValidateClientAsync(string clientId, string? clientSecret)
    {
        throw new NotImplementedException();
    }

    public Task<bool> HasConsentAsync(Guid userId, Guid clientId, string scope)
    {
        throw new NotImplementedException();
    }

    public Task GrantConsentAsync(Guid userId, Guid clientId, string scope)
    {
        throw new NotImplementedException();
    }

    public Task RevokeConsentAsync(Guid userId, Guid clientId)
    {
        throw new NotImplementedException();
    }

    public Task<bool> RevokeTokenAsync(string token, Guid clientId)
    {
        throw new NotImplementedException();
    }
}