using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SpiceAuth.Application.Interfaces;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Security;

/// <summary>
/// Generates JWT tokens using RS256 (RSA + SHA256).
/// </summary>
public class TokenService : ITokenService
{
    private readonly IKeyManagementService _keyManagement;
    private readonly IConfiguration _configuration;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _accessTokenLifetimeMinutes;

    public TokenService(
        IKeyManagementService keyManagement,
        IConfiguration configuration)
    {
        _keyManagement = keyManagement;
        _configuration = configuration;
        
        _issuer = configuration["JwtSettings:Issuer"] 
                  ?? throw new InvalidOperationException("JwtSettings:Issuer not configured");
        _audience = configuration["JwtSettings:Audience"] ?? "spiceauth";
        _accessTokenLifetimeMinutes = int.TryParse(configuration["JwtSettings:AccessTokenLifetimeMinutes"], out var lifetime) 
            ? lifetime 
            : 15;
    }

    public string GenerateAccessToken(
        User user, 
        string clientId, 
        string scope, 
        List<string> roles)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("username", user.Username),
            new("client_id", clientId)
        };

        // Add scopes (each scope as separate claim for easy validation)
        foreach (var s in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            claims.Add(new Claim("scope", s));
        }

        // Add roles (each role as separate claim)
        foreach (var role in roles)
        {
            claims.Add(new Claim("roles", role));
        }

        return GenerateToken(claims);
    }

    public string GenerateClientCredentialsToken(string clientId, string scope)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, $"client:{clientId}"),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("client_id", clientId)
        };

        // Add scopes
        foreach (var s in scope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            claims.Add(new Claim("scope", s));
        }

        return GenerateToken(claims);
    }

    public string GenerateRefreshToken()
    {
        // Generate cryptographically secure random token
        var randomBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        
        return Convert.ToBase64String(randomBytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    public string GetJwks()
    {
        var publicKeyJwk = _keyManagement.GetPublicKeyJwk();
        
        // JWKS format: array of keys
        return $"{{\"keys\":[{publicKeyJwk}]}}";
    }

    private string GenerateToken(List<Claim> claims)
    {
        var privateKey = _keyManagement.GetPrivateKey();
        var credentials = new SigningCredentials(
            new RsaSecurityKey(privateKey),
            SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };

        var now = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: now,
            expires: now.AddMinutes(_accessTokenLifetimeMinutes),
            signingCredentials: credentials
        );

        // Add key ID to header
        token.Header.Add("kid", _keyManagement.GetCurrentKeyId());

        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }
}