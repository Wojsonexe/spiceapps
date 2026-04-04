// SpiceAuth/Application/Services/MfaService.cs

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Services;

public class MfaService(
    UserManager<ApplicationUser> userManager,
    DbContext context)
{
    private const string AppName = "SpiceAuth";

    // ── SETUP ─────────────────────────────────────────────────
    public async Task<MfaSetupResponse> GenerateSetupAsync(Guid userId)
    {
        var user = await userManager.FindByIdAsync(userId.ToString())
            ?? throw new InvalidOperationException("Użytkownik nie znaleziony");

        await userManager.ResetAuthenticatorKeyAsync(user);
        var key = await userManager.GetAuthenticatorKeyAsync(user)
            ?? throw new InvalidOperationException("Nie udało się wygenerować klucza TOTP");

        var otpauthUri =
            $"otpauth://totp/{Uri.EscapeDataString(AppName)}:{Uri.EscapeDataString(user.Email!)}" +
            $"?secret={key}&issuer={Uri.EscapeDataString(AppName)}&algorithm=SHA1&digits=6&period=30";

        return new MfaSetupResponse(key, otpauthUri);
    }

    // ── ENABLE ────────────────────────────────────────────────
    public async Task<MfaEnableResponse> EnableMfaAsync(Guid userId, string code)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user == null) return new MfaEnableResponse(false, []);

        var isValid = await userManager.VerifyTwoFactorTokenAsync(
            user,
            userManager.Options.Tokens.AuthenticatorTokenProvider,
            code);

        if (!isValid) return new MfaEnableResponse(false, []);

        await userManager.SetTwoFactorEnabledAsync(user, true);

        var backupCodes = GenerateBackupCodes();
        
        var mfa = await context.Set<MfaSettings>()
            .FirstOrDefaultAsync(m => m.UserId == userId);

        if (mfa == null)
        {
            mfa = new MfaSettings { UserId = userId };
            context.Set<MfaSettings>().Add(mfa);
        }

        mfa.IsEnabled   = true;
        mfa.EnabledAt   = DateTime.UtcNow;
        mfa.BackupCodes = JsonSerializer.Serialize(backupCodes);

        await context.SaveChangesAsync();
        return new MfaEnableResponse(true, backupCodes);
    }

    // ── VERIFY ────────────────────────────────────────────────
    public async Task<bool> VerifyCodeAsync(Guid userId, string code)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user == null) return false;

        var mfa = await context.Set<MfaSettings>()
            .FirstOrDefaultAsync(m => m.UserId == userId && m.IsEnabled);

        if (mfa != null)
        {
            var codes = ParseBackupCodes(mfa.BackupCodes);
            if (codes.Contains(code))
            {
                codes.Remove(code);
                mfa.BackupCodes  = JsonSerializer.Serialize(codes);
                mfa.LastUsedAt   = DateTime.UtcNow;
                await context.SaveChangesAsync();
                return true;
            }
        }

        var result = await userManager.VerifyTwoFactorTokenAsync(
            user,
            userManager.Options.Tokens.AuthenticatorTokenProvider,
            code);

        if (result && mfa != null)
        {
            mfa.LastUsedAt = DateTime.UtcNow;
            await context.SaveChangesAsync();
        }

        return result;
    }

    // ── DISABLE ───────────────────────────────────────────────
    public async Task<bool> DisableMfaAsync(Guid userId, string code)
    {
        var isValid = await VerifyCodeAsync(userId, code);
        if (!isValid) return false;

        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user == null) return false;

        await userManager.SetTwoFactorEnabledAsync(user, false);
        await userManager.ResetAuthenticatorKeyAsync(user);

        var mfa = await context.Set<MfaSettings>()
            .FirstOrDefaultAsync(m => m.UserId == userId);

        if (mfa != null)
        {
            mfa.IsEnabled   = false;
            mfa.EnabledAt   = null;
            mfa.TotpSecret  = null;
            mfa.BackupCodes = null;
        }

        await context.SaveChangesAsync();
        return true;
    }

    // ── STATUS ────────────────────────────────────────────────
    public async Task<MfaStatusResponse> GetStatusAsync(Guid userId)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user == null) return new MfaStatusResponse(false, 0);

        var mfa = await context.Set<MfaSettings>()
            .FirstOrDefaultAsync(m => m.UserId == userId);

        return new MfaStatusResponse(
            IsEnabled:             user.TwoFactorEnabled,
            BackupCodesRemaining:  ParseBackupCodes(mfa?.BackupCodes).Count);
    }

    // ──────────────────────────────────
    public async Task<List<string>> RegenerateBackupCodesAsync(Guid userId, string code)
    {
        var isValid = await VerifyCodeAsync(userId, code);
        if (!isValid) return [];

        var mfa = await context.Set<MfaSettings>()
            .FirstOrDefaultAsync(m => m.UserId == userId && m.IsEnabled);

        if (mfa == null) return [];

        var newCodes    = GenerateBackupCodes();
        mfa.BackupCodes = JsonSerializer.Serialize(newCodes);
        await context.SaveChangesAsync();
        return newCodes;
    }

    // ── HELPERS ───────────────────────────────────────────────

    private static List<string> GenerateBackupCodes(int count = 8)
        => Enumerable.Range(0, count)
            .Select(_ => RandomNumberGenerator.GetHexString(8, lowercase: true))
            .ToList();

    private static List<string> ParseBackupCodes(string? json)
    {
        if (string.IsNullOrEmpty(json)) return [];
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? []; }
        catch { return []; }
    }
}

// ── DTOs ──────────────────────────────────────────────────────
public record MfaSetupResponse(string Secret, string OtpAuthUri);
public record MfaEnableResponse(bool Success, List<string> BackupCodes);
public record MfaStatusResponse(bool IsEnabled, int BackupCodesRemaining);
