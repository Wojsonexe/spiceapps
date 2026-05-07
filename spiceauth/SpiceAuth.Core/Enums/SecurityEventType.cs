namespace SpiceAuth.Core.Enums;

public enum SecurityEventType
{
    SuspiciousLogin = 0,
    MultipleFailedLogins = 1,
    UnrecognizedDevice = 2,
    PasswordChange = 3,
    MfaEnabled = 4,
    MfaDisabled = 5,
    AccountLocked = 6,
    UnusualActivity = 7,
    RefreshTokenReuseAttack = 8,
    BackchannelLogoutDispatched = 9,
    GlobalSessionRevoked = 10,
    PkceValidationFailed = 11,
    AuthorizationCodeReplay = 12,
    KeyRotated = 13,
    KeyRevoked = 14,
    CsrfViolation = 15,
    ProxySpoofAttempt = 16,
    ClientSecretCompromised = 17
}