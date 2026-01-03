namespace SpiceAuth.Core.Entities.Security;

public class JsonWebKey
{
    public string Kty { get; set; } = "RSA";
    public string Use { get; set; } = "sig";
    public string Kid { get; set; } = default!;
    public string Alg { get; set; } = "RS256";
    public string N { get; set; } = default!;
    public string E { get; set; } = default!;
}