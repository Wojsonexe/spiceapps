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

    // Security incidents
    RefreshTokenReuseAttack = 50,
    BackchannelLogoutDispatched = 51,
    GlobalSessionRevoked = 52,
    PkceValidationFailed = 53,
    AuthorizationCodeReplay = 54,
    KeyRotated = 55,
    KeyRevoked = 56,
    ClientSecretRotated2 = 57,   // v2 rotation audit (multiple-secret model)
    FederationDispatchFailed = 58,

    // Client secret lifecycle (3K)
    ClientSecretCreated = 60,
    ClientSecretRevoked = 61,
    ClientSecretUsed    = 62,
}
