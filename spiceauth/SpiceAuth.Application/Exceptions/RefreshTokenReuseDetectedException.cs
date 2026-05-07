namespace SpiceAuth.Application.Exceptions;

/// <summary>
/// Thrown when a refresh token that has already been used is presented again.
/// Signals a token theft / replay attack — the entire token family is revoked
/// and the user's GlobalSession is invalidated.
/// </summary>
public sealed class RefreshTokenReuseDetectedException(Guid userId, Guid? familyId)
    : Exception($"Refresh token reuse detected for user {userId} (family {familyId}). All sessions revoked.")
{
    public Guid UserId   { get; } = userId;
    public Guid? FamilyId { get; } = familyId;
}
