using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace SpiceAuth.Infrastructure.Services;

public class SmartPasswordHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    private readonly ILogger<SmartPasswordHasher<TUser>> _logger;

    public SmartPasswordHasher(ILogger<SmartPasswordHasher<TUser>> logger)
    {
        _logger = logger;
    }

    // Nowe hasła — zawsze Standard BCrypt
    public string HashPassword(TUser user, string password)
        => BCrypt.Net.BCrypt.HashPassword(password, workFactor: 13);

    public PasswordVerificationResult VerifyHashedPassword(
        TUser user, string hashedPassword, string providedPassword)
    {
        // 1. Próba Standard BCrypt (nowe hasła SpiceAuth)
        try
        {
            if (BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword))
            {
                // Sprawdź czy wymaga rehash (zmiana work factor)
                return BCrypt.Net.BCrypt.PasswordNeedsRehash(hashedPassword, 13)
                    ? PasswordVerificationResult.SuccessRehashNeeded
                    : PasswordVerificationResult.Success;
            }
        }
        catch
        {
            // Nie jest Standard BCrypt — próbuj Enhanced
        }

        // 2. Próba Enhanced BCrypt (stare hasła SpiceAPI)
        try
        {
            if (BCrypt.Net.BCrypt.EnhancedVerify(providedPassword, hashedPassword))
            {
                _logger.LogInformation(
                    "Legacy Enhanced BCrypt hash detected — will rehash on next save");

                // SuccessRehashNeeded → ASP.NET Identity automatycznie
                // wywoła HashPassword() i zapisze nowy Standard hash
                return PasswordVerificationResult.SuccessRehashNeeded;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Enhanced BCrypt verification failed");
        }

        return PasswordVerificationResult.Failed;
    }
}