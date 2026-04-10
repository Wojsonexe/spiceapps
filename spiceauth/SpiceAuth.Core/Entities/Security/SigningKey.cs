namespace SpiceAuth.Core.Entities.Security;

public class SigningKey
{
    public Guid Id { get; set; }
    public string KeyId { get; set; } = null!;
    public string Algorithm { get; set; } = "RS256";
    public string PublicKey { get; set; } = null!;
    public string PrivateKey { get; set; } = null!;
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ActivatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RetiredAt { get; set; }
}