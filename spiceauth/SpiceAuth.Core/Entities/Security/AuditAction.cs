namespace SpiceAuth.Core.Entities.Security;

public enum AuditAction
{
    // Auth
    Login = 0,
    Logout = 1,
    LoginFailed = 2,
    TokenRefreshed = 3,
    PasswordChanged = 4,
    TokenIssued = 5,

    // Registrations
    RegistrationApproved = 10,
    RegistrationRejected = 11,
    RegistrationCreated = 12,

    // Clients
    ClientRegistered = 20,
    ClientUpdated = 21,
    ClientDeleted = 22,
    ClientSecretRotated = 23,
    ClientStatusChanged = 24,

    // Users (admin)
    UserDeleted = 30,
    UserSuspended = 31,
    UserActivated = 32,
    UserRoleChanged = 33,
    
    ConsentGranted = 40,
    ConsentDenied = 41,
}
