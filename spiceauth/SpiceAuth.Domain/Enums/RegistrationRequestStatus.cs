namespace SpiceAuth.Domain.Enums;

/// <summary>
/// Status of a registration request.
/// </summary>
public enum RegistrationRequestStatus
{
    /// <summary>
    /// Request is awaiting admin review.
    /// </summary>
    Pending = 0,
    
    /// <summary>
    /// Request has been approved and user account created.
    /// </summary>
    Approved = 1,
    
    /// <summary>
    /// Request has been rejected by admin.
    /// </summary>
    Rejected = 2
}