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
    UnusualActivity = 7
}