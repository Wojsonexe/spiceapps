namespace SpiceAuth.Core.Entities.Security;

public class TokenPayload
{
    public string Sub { get; set; } = default!;
    public string Iss { get; set; } = default!;
    public string[] Aud { get; set; } = [];
    public long Exp { get; set; }
    public long Iat { get; set; }
    public long Nbf { get; set; }
    public string ClientId { get; set; } = default!;
    public string Scope { get; set; } = default!;
    public string[] Roles { get; set; } = [];
    public string? OrgId { get; set; }
    public string Jti { get; set; } = default!;
    public string? Azp { get; set; }
}