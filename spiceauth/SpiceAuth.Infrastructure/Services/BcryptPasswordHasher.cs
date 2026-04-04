using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;

namespace SpiceAuth.Infrastructure.Services;

public class BcryptPasswordHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    private readonly int _workFactor;
    private readonly PasswordHasher<TUser> _fallback = new();

    public BcryptPasswordHasher(IConfiguration config)
    {
        _workFactor = int.TryParse(config["Crypto:WorkFactor"], out var wf) ? wf : 14;
    }

    public string HashPassword(TUser user, string password)
        => BCrypt.Net.BCrypt.EnhancedHashPassword(password, _workFactor);

    public PasswordVerificationResult VerifyHashedPassword(
        TUser user, string hashedPassword, string providedPassword)
    {
        if (!hashedPassword.StartsWith("$2"))
        {
            var result = _fallback.VerifyHashedPassword(user, hashedPassword, providedPassword);
            return result == PasswordVerificationResult.Success
                ? PasswordVerificationResult.SuccessRehashNeeded
                : result;
        }

        bool valid = BCrypt.Net.BCrypt.EnhancedVerify(providedPassword, hashedPassword);
        if (!valid) return PasswordVerificationResult.Failed;

        return BCrypt.Net.BCrypt.PasswordNeedsRehash(hashedPassword, _workFactor)
            ? PasswordVerificationResult.SuccessRehashNeeded
            : PasswordVerificationResult.Success;
    }
}