namespace SpiceAuth.Core.Enums;

public enum AuditAction
{
    // Authentication
    Login = 0,
    Logout = 1,
    LoginFailed = 2,
    
    // Token operations
    TokenIssued = 10,
    TokenRefreshed = 11,
    TokenRevoked = 12,
    
    // User management
    UserCreated = 20,
    UserUpdated = 21,
    UserDeleted = 22,
    UserSuspended = 23,
    UserActivated = 24,
    
    // Registration
    RegistrationRequested = 30,
    RegistrationApproved = 31,
    RegistrationRejected = 32,
    
    // Authorization
    ScopeGranted = 40,
    ScopeRevoked = 41,
    RoleAssigned = 42,
    RoleRemoved = 43,
    ConsentGranted = 44,
    ConsentRevoked = 45,
    
    // Organization
    OrganizationCreated = 50,
    OrganizationMemberAdded = 51,
    OrganizationMemberRemoved = 52,
    
    // Security
    MfaEnabled = 60,
    MfaDisabled = 61,
    MfaVerified = 62,
    PasswordChanged = 63,
    AccountLocked = 64,
    
    // OAuth Client
    ClientCreated = 70,
    ClientUpdated = 71,
    ClientDeleted = 72
}