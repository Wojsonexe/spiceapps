namespace SpiceAuth.Application.Exceptions;

public sealed class PkceException(string reason)
    : Exception($"PKCE validation failed: {reason}")
{
    public string Reason { get; } = reason;
}
