namespace SpiceAuth.Application.Exceptions;

public sealed class OAuthException : Exception
{
    public string Error { get; }
    public string? ErrorDescription { get; }
    public string? ErrorUri { get; }

    public OAuthException(
        string error,
        string? description = null,
        string? errorUri = null) 
        : base(description ?? error)
    {
        Error = error;
        ErrorDescription = description;
        ErrorUri = errorUri;
    }
}