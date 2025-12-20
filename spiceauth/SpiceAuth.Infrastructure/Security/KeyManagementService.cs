using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Interfaces;

namespace SpiceAuth.Infrastructure.Security;

/// <summary>
/// Manages RSA key pairs for JWT signing and validation.
/// In development: generates and stores keys in memory.
/// In production: loads keys from secure storage (files, Azure Key Vault, etc.)
/// </summary>
public class KeyManagementService : IKeyManagementService
{
    private readonly ILogger<KeyManagementService> _logger;
    private readonly IConfiguration _configuration;
    private RSA? _privateKey;
    private RSA? _publicKey;
    private readonly string _keyId;

    public KeyManagementService(
        ILogger<KeyManagementService> logger,
        IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
        _keyId = $"spiceauth-{DateTime.UtcNow:yyyy-MM}"; // Monthly key rotation identifier
        
        InitializeKeys();
    }

    private void InitializeKeys()
    {
        var privateKeyPath = _configuration["JwtSettings:PrivateKeyPath"];
        var publicKeyPath = _configuration["JwtSettings:PublicKeyPath"];

        if (!string.IsNullOrEmpty(privateKeyPath) && File.Exists(privateKeyPath))
        {
            // Load from files (production)
            LoadKeysFromFiles(privateKeyPath, publicKeyPath);
        }
        else
        {
            // Generate in-memory (development)
            GenerateKeysInMemory();
        }
    }

    private void LoadKeysFromFiles(string privateKeyPath, string? publicKeyPath)
    {
        try
        {
            // Load private key
            var privateKeyPem = File.ReadAllText(privateKeyPath);
            _privateKey = RSA.Create();
            _privateKey.ImportFromPem(privateKeyPem);

            // Load public key (or derive from private key)
            if (!string.IsNullOrEmpty(publicKeyPath) && File.Exists(publicKeyPath))
            {
                var publicKeyPem = File.ReadAllText(publicKeyPath);
                _publicKey = RSA.Create();
                _publicKey.ImportFromPem(publicKeyPem);
            }
            else
            {
                // Derive public key from private key
                _publicKey = RSA.Create();
                _publicKey.ImportParameters(_privateKey.ExportParameters(false));
            }

            _logger.LogInformation("Loaded RSA keys from files");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load RSA keys from files, generating new keys");
            GenerateKeysInMemory();
        }
    }

    private void GenerateKeysInMemory()
    {
        _logger.LogWarning("Generating RSA keys in memory - NOT suitable for production!");
        
        _privateKey = RSA.Create(2048);
        _publicKey = RSA.Create();
        _publicKey.ImportParameters(_privateKey.ExportParameters(false));

        // Optionally save to disk for development persistence
        var devKeysPath = Path.Combine(Directory.GetCurrentDirectory(), "dev_keys");
        if (!Directory.Exists(devKeysPath))
        {
            Directory.CreateDirectory(devKeysPath);
            
            // Save keys
            File.WriteAllText(
                Path.Combine(devKeysPath, "private.pem"),
                _privateKey.ExportRSAPrivateKeyPem());
            
            File.WriteAllText(
                Path.Combine(devKeysPath, "public.pem"),
                _publicKey.ExportRSAPublicKeyPem());
            
            _logger.LogInformation("Saved development keys to {Path}", devKeysPath);
        }
    }

    public RSA GetPrivateKey()
    {
        if (_privateKey == null)
            throw new InvalidOperationException("Private key not initialized");
        
        return _privateKey;
    }

    public RSA GetPublicKey()
    {
        if (_publicKey == null)
            throw new InvalidOperationException("Public key not initialized");
        
        return _publicKey;
    }

    public string GetCurrentKeyId()
    {
        return _keyId;
    }

    public string GetPublicKeyJwk()
    {
        var parameters = GetPublicKey().ExportParameters(false);
        
        var jwk = new
        {
            kty = "RSA",
            use = "sig",
            kid = _keyId,
            alg = "RS256",
            n = Base64UrlEncode(parameters.Modulus!),
            e = Base64UrlEncode(parameters.Exponent!)
        };

        return JsonSerializer.Serialize(jwk);
    }

    private static string Base64UrlEncode(byte[] input)
    {
        var base64 = Convert.ToBase64String(input);
        return base64
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}