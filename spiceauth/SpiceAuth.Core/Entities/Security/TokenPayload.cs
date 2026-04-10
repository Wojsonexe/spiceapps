namespace SpiceAuth.Core.Entities.Security;

public class TokenPayload
{
    public string Sub { get; set; } = null!;
    public string Iss { get; set; } = null!;
    public string[] Aud { get; set; } = null!;
    public long Exp { get; set; }
    public long Iat { get; set; }
    public long Nbf { get; set; }
    public string ClientId { get; set; } = null!;
    public string Scope { get; set; } = null!;
    public string[] Roles { get; set; } = null!;
    public string? OrgId { get; set; }
    public string Jti { get; set; } = null!;
}