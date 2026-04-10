using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Services;

/// <summary>
/// Production-grade TokenService implementing OAuth2 / OIDC best practices.
/// Handles: access tokens, ID tokens, JWKS, key rotation, refresh token lifecycle.
/// </summary>
public class TokenService(
    DbContext context,
    IKeyManagementService keyManagement,
    IConfiguration configuration,
    ILogger<TokenService> logger) : ITokenService
{
    private readonly DbContext _context = context;
    private readonly IKeyManagementService _keyManagement = keyManagement;
    private readonly IConfiguration _configuration = configuration;
    private readonly ILogger<TokenService> _logger = logger;

    // ─── Configuration ────────────────────────────────────────────────────────

    private string Issuer =>
        _configuration["Jwt:Issuer"] ?? "https://auth.team5883.pl";

    private string DefaultAudience =>
        _configuration["Jwt:Audience"] ?? "spiceapi";

    private int AccessTokenLifetime =>
        int.TryParse(_configuration["Jwt:AccessTokenLifetime"], out var v) ? v : 900;

    private int RefreshTokenLifetime =>
        int.TryParse(_configuration["Jwt:RefreshTokenLifetime"], out var v) ? v : 604800;

    private int IdTokenLifetime =>
        int.TryParse(_configuration["Jwt:IdTokenLifetime"], out var v) ? v : 3600;

    // ─── Access Token ─────────────────────────────────────────────────────────

    public async Task<string> GenerateAccessTokenAsync(TokenRequest request)
    {
        var (credentials, kid) = await BuildSigningCredentialsAsync();

        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(AccessTokenLifetime);

        var user = await _context.Set<ApplicationUser>()
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == request.UserId);

        var claims = BuildBaseClaims(request.UserId, now);

        claims.Add(new Claim("client_id", request.ClientId.ToString()));

        if (!string.IsNullOrWhiteSpace(request.Scope))
            foreach (var scope in request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                claims.Add(new Claim("scope", scope));

        if (user is not null)
            AddUserClaims(claims, user);

        if (request.Roles?.Length > 0)
            foreach (var role in request.Roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

        if (request.OrganizationId.HasValue)
            claims.Add(new Claim("org_id", request.OrganizationId.Value.ToString()));

        if (!string.IsNullOrWhiteSpace(request.Nonce))
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, request.Nonce));

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = Issuer,
            Audience = DefaultAudience,
            NotBefore = now,
            Expires = expires,
            SigningCredentials = credentials
        };

        var token = WriteToken(descriptor, kid);

        _logger.LogDebug("Generated access token for user {UserId}", request.UserId);
        return token;
    }

    // ─── ID Token (OIDC) ──────────────────────────────────────────────────────

    /// <summary>
    /// Generates an OIDC ID Token per spec:
    /// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// </summary>
    public async Task<string> GenerateIdTokenAsync(
        Guid userId,
        Guid clientId,
        string nonce,
        string[]? audiences = null)
    {
        var (credentials, kid) = await BuildSigningCredentialsAsync();

        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(IdTokenLifetime);

        var user = await _context.Set<ApplicationUser>()
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId);

        var claims = BuildBaseClaims(userId, now);

        // OIDC required: auth_time
        claims.Add(new Claim("auth_time",
            new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
            ClaimValueTypes.Integer64));

        if (!string.IsNullOrWhiteSpace(nonce))
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));

        if (user is not null)
            AddUserClaims(claims, user);

        // ID token audience = clientId (OIDC spec §2)
        var aud = audiences?.Length > 0
            ? string.Join(" ", audiences)
            : clientId.ToString();

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = Issuer,
            Audience = aud,
            NotBefore = now,
            Expires = expires,
            SigningCredentials = credentials
        };

        var token = WriteToken(descriptor, kid, tokenType: "JWT");

        _logger.LogDebug("Generated ID token for user {UserId}, client {ClientId}", userId, clientId);
        return token;
    }

    // ─── Refresh Token ────────────────────────────────────────────────────────

    /// <summary>
    /// Issues a new refresh token with rotation support.
    /// Pass previousTokenId to link in the rotation chain.
    /// </summary>
    public async Task<string> GenerateRefreshTokenAsync(
        Guid userId,
        Guid clientId,
        string scope,
        Guid? organizationId = null,
        string? deviceId = null,
        Guid? familyId = null,
        Guid? previousTokenId = null)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var tokenHash = HashToken(rawToken);
        var newFamilyId = familyId ?? Guid.NewGuid();

        var entity = new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = tokenHash,
            ClientId = clientId,
            UserId = userId,
            DeviceId = deviceId,
            Scope = scope,
            IsRevoked = false,
            IsUsed = false,
            FamilyId = newFamilyId,
            ReplacedByTokenId = null,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddSeconds(RefreshTokenLifetime),
            OrganizationId = organizationId
        };

        _context.Set<RefreshToken>().Add(entity);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Issued refresh token for user {UserId}, family {FamilyId}",
            userId, newFamilyId);

        return rawToken;
    }

    // Satisfy original interface signature (no deviceId / familyId overload needed externally)
    public Task<string> GenerateRefreshTokenAsync(
        Guid userId,
        Guid clientId,
        string scope,
        Guid? organizationId = null)
        => GenerateRefreshTokenAsync(userId, clientId, scope, organizationId, null, null, null);

    // ─── Refresh Token Rotation + Reuse Detection ─────────────────────────────

    /// <summary>
    /// Validates incoming refresh token, detects reuse attacks, rotates to a new token.
    /// Returns (newAccessToken, newRefreshToken) or throws on security violation.
    /// </summary>
    public async Task<(string AccessToken, string NewRefreshToken)> RotateRefreshTokenAsync(
        string incomingRawToken,
        Guid clientId,
        string scope)
    {
        var hash = HashToken(incomingRawToken);

        var existing = await _context.Set<RefreshToken>()
            .FirstOrDefaultAsync(t => t.TokenHash == hash && t.ClientId == clientId);

        if (existing is null)
        {
            _logger.LogWarning("Refresh token not found for client {ClientId}", clientId);
            throw new SecurityTokenException("Invalid refresh token.");
        }

        // ── Reuse detection ──────────────────────────────────────────────────
        if (existing.IsUsed)
        {
            _logger.LogWarning(
                "⚠️  Refresh token REUSE detected for user {UserId}, family {FamilyId}. Revoking all family tokens.",
                existing.UserId, existing.FamilyId);

            await RevokeTokenFamilyAsync(existing.FamilyId);

            throw new SecurityTokenException("Refresh token reuse detected. All sessions revoked.");
        }

        if (existing.IsRevoked)
            throw new SecurityTokenException("Refresh token has been revoked.");

        if (existing.ExpiresAt < DateTime.UtcNow)
            throw new SecurityTokenException("Refresh token has expired.");

        // ── Mark current token as used ───────────────────────────────────────
        existing.IsUsed = true;
        existing.IsRevoked = true;

        // ── Issue rotated token ──────────────────────────────────────────────
        var newRaw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var newHash = HashToken(newRaw);

        var newToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = newHash,
            ClientId = clientId,
            UserId = existing.UserId,
            DeviceId = existing.DeviceId,
            Scope = existing.Scope,
            IsRevoked = false,
            IsUsed = false,
            FamilyId = existing.FamilyId,
            ReplacedByTokenId = null,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddSeconds(RefreshTokenLifetime),
            OrganizationId = existing.OrganizationId
        };

        existing.ReplacedByTokenId = newToken.Id;
        _context.Set<RefreshToken>().Add(newToken);
        await _context.SaveChangesAsync();

        // ── Generate new access token ────────────────────────────────────────
        var accessToken = await GenerateAccessTokenAsync(new TokenRequest
        {
            UserId = existing.UserId,
            ClientId = clientId,
            Scope = existing.Scope,
            OrganizationId = existing.OrganizationId
        });

        return (accessToken, newRaw);
    }

    // ─── Validate Token ───────────────────────────────────────────────────────

    public async Task<TokenPayload?> ValidateTokenAsync(string token)
    {
        var keys = await _keyManagement.GetActiveKeysAsync();
        var handler = new JwtSecurityTokenHandler();

        foreach (var key in keys)
        {
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(Convert.FromBase64String(key.PublicKey), out _);

                var parameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = Issuer,
                    ValidateAudience = true,
                    ValidAudiences = new[] { DefaultAudience },
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new RsaSecurityKey(rsa),
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                handler.ValidateToken(token, parameters, out var validatedToken);

                if (validatedToken is not JwtSecurityToken jwt) continue;

                return new TokenPayload
                {
                    Sub = jwt.Subject!,
                    Iss = jwt.Issuer!,
                    Aud = jwt.Audiences.ToArray(),
                    Exp = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds(),
                    Iat = long.Parse(jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Iat).Value),
                    Nbf = new DateTimeOffset(jwt.ValidFrom).ToUnixTimeSeconds(),
                    ClientId = jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value ?? "",
                    Scope = string.Join(" ", jwt.Claims.Where(c => c.Type == "scope").Select(c => c.Value)),
                    Roles = jwt.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToArray(),
                    OrgId = jwt.Claims.FirstOrDefault(c => c.Type == "org_id")?.Value,
                    Jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value ?? ""
                };
            }
            catch
            {
                // try next key
            }
        }

        _logger.LogWarning("Token validation failed against all active keys");
        return null;
    }

    // ─── JWKS ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns /.well-known/jwks.json compatible key set.
    /// All active (including recently-retired) public keys are included
    /// so tokens signed by a rotated key remain verifiable until they expire.
    /// </summary>
    public async Task<JwksResponse> GetJwksAsync()
    {
        var keys = await _keyManagement.GetActiveKeysAsync();
        var jwks = new JwksResponse();

        foreach (var key in keys)
        {
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(Convert.FromBase64String(key.PublicKey), out _);
                var rsaParams = rsa.ExportParameters(includePrivateParameters: false);

                jwks.Keys.Add(new JwkKey
                {
                    Kid = key.KeyId,
                    Kty = "RSA",
                    Use = "sig",
                    Alg = "RS256",
                    N = Base64UrlEncode(rsaParams.Modulus!),
                    E = Base64UrlEncode(rsaParams.Exponent!)
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export JWK for key {KeyId}", key.KeyId);
            }
        }

        return jwks;
    }

    // ─── Active Signing Key ───────────────────────────────────────────────────

    /// <summary>
    /// Returns the currently active signing key (used for new tokens).
    /// </summary>
    public async Task<SigningKey> GetActiveSigningKeyAsync()
    {
        return await _keyManagement.GetActiveKeyAsync();
    }

    // ─── Key Rotation ─────────────────────────────────────────────────────────

    /// <summary>
    /// Rotates the RSA signing key:
    /// 1. Generates a new 2048-bit RSA key pair
    /// 2. Stores it as the new active key
    /// 3. Marks the previous key as retired (still returned by GetActiveKeysAsync
    ///    so existing tokens remain verifiable until their expiry)
    /// Call this on a schedule (e.g. every 30 days via Hangfire / cron).
    /// </summary>
    public async Task RotateKeysAsync()
    {
        _logger.LogInformation("Starting key rotation...");

        // Generate new key
        using var rsa = RSA.Create(2048);
        var privateKeyBytes = rsa.ExportRSAPrivateKey();
        var publicKeyBytes = rsa.ExportRSAPublicKey();

        var newKey = new SigningKey
        {
            Id = Guid.NewGuid(),
            KeyId = GenerateKid(),
            PublicKey = Convert.ToBase64String(publicKeyBytes),
            PrivateKey = Convert.ToBase64String(privateKeyBytes),
            IsActive = true,
            CreatedAt = DateTime.UtcNow
        };

        // Retire current active key (keep it so existing tokens still validate)
        var currentKey = await _context.Set<SigningKey>()
            .Where(k => k.IsActive)
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefaultAsync();

        if (currentKey is not null)
        {
            currentKey.IsActive = false;
            currentKey.RetiredAt = DateTime.UtcNow;
            _logger.LogInformation("Retired key {Kid}", currentKey.KeyId);
        }

        _context.Set<SigningKey>().Add(newKey);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Key rotation complete. New active key: {Kid}", newKey.KeyId);
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    private async Task<(SigningCredentials Credentials, string Kid)> BuildSigningCredentialsAsync()
    {
        var key = await _keyManagement.GetActiveKeyAsync();

        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(key.PrivateKey), out _);

        // Export to new instance so the using block above doesn't dispose what we pass in
        var rsaClone = RSA.Create();
        rsaClone.ImportRSAPrivateKey(Convert.FromBase64String(key.PrivateKey), out _);

        var secKey = new RsaSecurityKey(rsaClone) { KeyId = key.KeyId };

        var credentials = new SigningCredentials(secKey, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        return (credentials, key.KeyId);
    }

    private string WriteToken(SecurityTokenDescriptor descriptor, string kid, string tokenType = "at+jwt")
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(descriptor);

        if (token is JwtSecurityToken jwt)
        {
            jwt.Header["kid"] = kid;
            jwt.Header["typ"] = tokenType;
        }

        return handler.WriteToken(token);
    }

    private static List<Claim> BuildBaseClaims(Guid userId, DateTime now) =>
        new()
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };

    private static void AddUserClaims(List<Claim> claims, ApplicationUser user)
    {
        if (!string.IsNullOrEmpty(user.Email))
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));

        if (!string.IsNullOrEmpty(user.FirstName))
            claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName));

        if (!string.IsNullOrEmpty(user.LastName))
            claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName));

        claims.Add(new Claim("department", user.Department.ToString()));
        claims.Add(new Claim("is_approved", user.IsApproved.ToString().ToLower()));

        if (!string.IsNullOrEmpty(user.DiscordId))
            claims.Add(new Claim("discord_id", user.DiscordId));
    }

    private async Task RevokeTokenFamilyAsync(Guid? familyId)
    {
        if (familyId is null) return;

        var familyTokens = await _context.Set<RefreshToken>()
            .Where(t => t.FamilyId == familyId && !t.IsRevoked)
            .ToListAsync();

        foreach (var t in familyTokens)
        {
            t.IsRevoked = true;
            t.IsUsed = true;
        }

        await _context.SaveChangesAsync();

        _logger.LogWarning("Revoked {Count} tokens in family {FamilyId}", familyTokens.Count, familyId);
    }

    private static string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        return Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string GenerateKid() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(8))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}