using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Services;

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

    private string Issuer => _configuration["Jwt:Issuer"] ?? "https://auth.team5883.pl";
    private int AccessTokenLifetime =>
        int.TryParse(_configuration["Jwt:AccessTokenLifetime"], out var val) ? val : 900;

    private int RefreshTokenLifetime =>
        int.TryParse(_configuration["Jwt:RefreshTokenLifetime"], out var val) ? val : 604800;

    // ============================================================
    // ACCESS TOKEN
    // ============================================================

    public async Task<string> GenerateAccessTokenAsync(TokenRequest request)
    {
        var key = await _keyManagement.GetActiveKeyAsync();

        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(key.PrivateKey), out _);

        var signingCredentials = new SigningCredentials(
            new RsaSecurityKey(rsa),
            SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory
            {
                CacheSignatureProviders = false
            }
        };

        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(AccessTokenLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, request.UserId.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(
                JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new("client_id", request.ClientId.ToString()),
            new("scope", request.Scope)
        };

        if (request.Roles != null && request.Roles.Any())
        {
            foreach (var role in request.Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }

        if (request.OrganizationId.HasValue)
        {
            claims.Add(new Claim("org_id", request.OrganizationId.Value.ToString()));
        }

        if (!string.IsNullOrEmpty(request.Nonce))
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, request.Nonce));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = Issuer,
            Audience = "spiceauth",
            NotBefore = now,
            Expires = expires,
            SigningCredentials = signingCredentials
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(descriptor);

        if (token is JwtSecurityToken jwt)
        {
            jwt.Header["kid"] = key.KeyId;
        }

        _logger.LogDebug(
            "Generated access token for user {UserId}, client {ClientId}",
            request.UserId,
            request.ClientId);

        return handler.WriteToken(token);
    }

    public async Task<string> GenerateRefreshTokenAsync(
        Guid userId,
        Guid clientId,
        string scope,
        Guid? organizationId = null)
    {
        var randomBytes = RandomNumberGenerator.GetBytes(32);
        var token = Convert.ToBase64String(randomBytes);
        var tokenHash = HashToken(token);

        var refreshToken = new RefreshToken
        {
            Id = Guid.NewGuid(),
            TokenHash = tokenHash,
            ClientId = clientId,
            UserId = userId,
            Scope = scope,
            IsRevoked = false,
            IsUsed = false,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddSeconds(RefreshTokenLifetime),
            OrganizationId = organizationId
        };

        _context.Set<RefreshToken>().Add(refreshToken);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Generated refresh token for user {UserId}", userId);

        return token;
    }

    public async Task<string> GenerateIdTokenAsync(
        Guid userId,
        Guid clientId,
        string nonce,
        string[]? audiences = null)
    {
        var user = await _context.Set<Core.Entities.Identity.User>()
            .FirstOrDefaultAsync(u => u.Id == userId);

        if (user == null)
            throw new InvalidOperationException("User not found");

        var key = await _keyManagement.GetActiveKeyAsync();

        using var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(Convert.FromBase64String(key.PrivateKey), out _);

        var signingCredentials = new SigningCredentials(
            new RsaSecurityKey(rsa),
            SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory
            {
                CacheSignatureProviders = false
            }
        };

        var now = DateTime.UtcNow;

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, userId.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new("email_verified", user.EmailConfirmed ? "true" : "false"),
            new("preferred_username", user.Username),
            new(
                JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Nonce, nonce),
            new("azp", clientId.ToString())
        };

        if (!string.IsNullOrEmpty(user.FirstName))
            claims.Add(new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName));

        if (!string.IsNullOrEmpty(user.LastName))
            claims.Add(new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName));

        if (!string.IsNullOrEmpty(user.ProfilePictureUrl))
            claims.Add(new Claim("picture", user.ProfilePictureUrl));

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = Issuer,
            Audience = clientId.ToString(),
            NotBefore = now,
            Expires = now.AddMinutes(15),
            SigningCredentials = signingCredentials
        };

        var handler = new JwtSecurityTokenHandler();
        var token = handler.CreateToken(descriptor);

        if (token is JwtSecurityToken jwt)
        {
            jwt.Header["kid"] = key.KeyId;
        }

        return handler.WriteToken(token);
    }

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
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new RsaSecurityKey(rsa),
                    ClockSkew = TimeSpan.FromMinutes(5)
                };

                handler.ValidateToken(token, parameters, out var validatedToken);

                if (validatedToken is not JwtSecurityToken jwt)
                    continue;

                return new TokenPayload
                {
                    Sub = jwt.Subject!,
                    Iss = jwt.Issuer!,
                    Aud = jwt.Audiences.ToArray(),
                    Exp = new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds(),
                    Iat = long.Parse(jwt.Claims.First(c => c.Type == JwtRegisteredClaimNames.Iat).Value),
                    Nbf = new DateTimeOffset(jwt.ValidFrom).ToUnixTimeSeconds(),
                    ClientId = jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value ?? "",
                    Scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value ?? "",
                    Roles = jwt.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToArray(),
                    OrgId = jwt.Claims.FirstOrDefault(c => c.Type == "org_id")?.Value,
                    Jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value ?? "",
                    Azp = jwt.Claims.FirstOrDefault(c => c.Type == "azp")?.Value
                };
            }
            catch
            {
                continue;
            }
        }

        _logger.LogWarning("Failed to validate token with any active key");
        return null;
    }

    public async Task<JwksResponse> GetJwksAsync()
    {
        var keys = await _keyManagement.GetActiveKeysAsync();

        return new JwksResponse
        {
            Keys = keys.Select(k =>
            {
                using var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(Convert.FromBase64String(k.PublicKey), out _);
                var p = rsa.ExportParameters(false);

                return new SpiceAuth.Core.Entities.Security.JsonWebKey
                {
                    Kty = "RSA",
                    Use = "sig",
                    Kid = k.KeyId,
                    Alg = "RS256",
                    N = Base64UrlEncoder.Encode(p.Modulus),
                    E = Base64UrlEncoder.Encode(p.Exponent)
                };
            }).ToList()
        };
    }

    public Task<SigningKey> GetActiveSigningKeyAsync() =>
        _keyManagement.GetActiveKeyAsync();

    public Task RotateKeysAsync() =>
        _keyManagement.RotateKeysAsync();
    private static string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        return Convert.ToBase64String(
            sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));
    }
}
