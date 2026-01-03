namespace SpiceAuth.Core.Entities.Security;

public class SigningKey : BaseEntity
{
    public string KeyId { get; set; } = null!; // "kid" for JWKS
    public string Algorithm { get; set; } = "RS256";
    public string PublicKey { get; set; } = null!; // PEM format
    public string PrivateKey { get; set; } = null!; // PEM format, encrypted at rest
    
    public bool IsActive { get; set; }
    public DateTime? ActivatedAt { get; set; }
    public DateTime? RetiredAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}