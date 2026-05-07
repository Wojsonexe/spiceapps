using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Abstractions.Persistence;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Core.Entities.OAuth;

namespace SpiceAuth.Infrastructure.Services;

public class FederationService(
    IApplicationDbContext context,
    ILogger<FederationService> logger) : IFederationService
{
    private static readonly TimeSpan SessionTtl = TimeSpan.FromHours(8);

    // ─── CreateGlobalSession ──────────────────────────────────────────────────

    public async Task<GlobalSession> CreateGlobalSessionAsync(
        Guid userId, string? ipAddress, string? userAgent)
    {
        var sid = GenerateSid();

        var session = new GlobalSession
        {
            Id                = Guid.NewGuid(),
            Sid               = sid,
            UserId            = userId,
            CreatedAt         = DateTime.UtcNow,
            ExpiresAt         = DateTime.UtcNow.Add(SessionTtl),
            LastActivityAt    = DateTime.UtcNow,
            IpAddress         = ipAddress,
            UserAgent         = userAgent,
            DeviceFingerprint = ComputeFingerprint(userAgent, ipAddress)
        };

        context.GlobalSessions.Add(session);
        await context.SaveChangesAsync();

        logger.LogInformation("GlobalSession created for user {UserId} (sid=…{Suffix})",
            userId, Tail(sid));

        return session;
    }

    // ─── GetActiveGlobalSession ───────────────────────────────────────────────

    public async Task<GlobalSession?> GetActiveGlobalSessionAsync(string sid)
    {
        return await context.GlobalSessions
            .Include(s => s.AppSessions)
            .FirstOrDefaultAsync(s =>
                s.Sid == sid &&
                s.RevokedAt == null &&
                s.ExpiresAt > DateTime.UtcNow);
    }

    // ─── RevokeGlobalSession ──────────────────────────────────────────────────

    public async Task RevokeGlobalSessionAsync(string sid)
    {
        var rows = await context.GlobalSessions
            .Where(s => s.Sid == sid && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(gs => gs.RevokedAt, DateTime.UtcNow));

        if (rows == 0)
            logger.LogDebug("RevokeGlobalSession: sid not found or already revoked (…{Suffix})", Tail(sid));
        else
            logger.LogInformation("GlobalSession revoked (…{Suffix})", Tail(sid));
    }

    // ─── RegisterAppSession ───────────────────────────────────────────────────

    public async Task RegisterAppSessionAsync(
        string sid, string appName, string? localSessionId,
        string backchannelLogoutUri, string clientId, string clientSecret)
    {
        var globalSession = await context.GlobalSessions
            .FirstOrDefaultAsync(s =>
                s.Sid == sid &&
                s.RevokedAt == null &&
                s.ExpiresAt > DateTime.UtcNow);

        if (globalSession == null)
            throw new InvalidOperationException("GlobalSession not found, revoked, or expired");

        // Validate client credentials
        var client = await context.OAuthClients
            .FirstOrDefaultAsync(c => c.ClientId == clientId && c.IsActive);

        if (client == null)
            throw new UnauthorizedAccessException("Unknown or inactive client");

        if (!string.IsNullOrEmpty(client.ClientSecretHash) &&
            !BCrypt.Net.BCrypt.Verify(clientSecret, client.ClientSecretHash))
            throw new UnauthorizedAccessException("Invalid client secret");

        // Upsert AppSession (idempotent)
        var existing = await context.AppSessions
            .FirstOrDefaultAsync(a =>
                a.GlobalSessionId == globalSession.Id &&
                a.AppName == appName);

        if (existing != null)
        {
            existing.LocalSessionId       = localSessionId ?? existing.LocalSessionId;
            existing.BackchannelLogoutUri = backchannelLogoutUri;
            existing.LastSeenAt           = DateTime.UtcNow;
        }
        else
        {
            context.AppSessions.Add(new AppSession
            {
                Id                   = Guid.NewGuid(),
                GlobalSessionId      = globalSession.Id,
                AppName              = appName,
                LocalSessionId       = localSessionId,
                BackchannelLogoutUri = backchannelLogoutUri,
                RegisteredAt         = DateTime.UtcNow,
                LastSeenAt           = DateTime.UtcNow
            });
        }

        globalSession.LastActivityAt = DateTime.UtcNow;
        await context.SaveChangesAsync();

        logger.LogInformation("AppSession registered: app={App} (…{Suffix})", appName, Tail(sid));
    }

    // ─── RevokeAndDispatch ────────────────────────────────────────────────────

    public async Task RevokeAndDispatchAsync(string sid, string clientId, string clientSecret)
    {
        var session = await context.GlobalSessions
            .Include(s => s.AppSessions)
            .FirstOrDefaultAsync(s => s.Sid == sid);

        if (session == null)
        {
            logger.LogWarning("RevokeAndDispatch: sid not found (…{Suffix})", Tail(sid));
            return;
        }

        if (!session.RevokedAt.HasValue)
        {
            session.RevokedAt = DateTime.UtcNow;
            logger.LogInformation("GlobalSession revoked for dispatch (…{Suffix})", Tail(sid));
        }

        if (session.AppSessions.Count == 0)
        {
            await context.SaveChangesAsync();
            return;
        }

        // Enqueue a durable FederationDispatch row for each registered app.
        // FederationDispatchWorker will handle actual delivery with retries.
        EnqueueDispatches(session.Id, sid, session.AppSessions);
        await context.SaveChangesAsync();

        logger.LogInformation("Enqueued {Count} backchannel dispatch(es) for sid=…{Suffix}",
            session.AppSessions.Count, Tail(sid));
    }

    // ─── GetUserSessions ──────────────────────────────────────────────────────

    public async Task<IReadOnlyList<GlobalSession>> GetUserSessionsAsync(Guid userId)
    {
        return await context.GlobalSessions
            .Include(s => s.AppSessions)
            .Where(s => s.UserId == userId)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync();
    }

    // ─── RevokeAllUserSessions ────────────────────────────────────────────────

    public async Task RevokeAllUserSessionsAsync(Guid userId)
    {
        var activeSessions = await context.GlobalSessions
            .Include(s => s.AppSessions)
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > DateTime.UtcNow)
            .ToListAsync();

        if (activeSessions.Count == 0) return;

        var now = DateTime.UtcNow;
        foreach (var session in activeSessions)
            session.RevokedAt = now;

        // Enqueue durable dispatch for every app registered to every session
        foreach (var session in activeSessions)
            EnqueueDispatches(session.Id, session.Sid, session.AppSessions);

        await context.SaveChangesAsync();

        logger.LogWarning(
            "RevokeAllUserSessions: revoked {Count} sessions for user {UserId}, enqueued dispatch rows",
            activeSessions.Count, userId);
    }

    // ─── Private helpers ──────────────────────────────────────────────────────

    private void EnqueueDispatches(Guid globalSessionId, string sid, IEnumerable<AppSession> apps)
    {
        foreach (var app in apps)
        {
            context.FederationDispatches.Add(new FederationDispatch
            {
                Id                   = Guid.NewGuid(),
                GlobalSessionId      = globalSessionId,
                Sid                  = sid,
                AppName              = app.AppName,
                BackchannelLogoutUri = app.BackchannelLogoutUri,
                LogoutToken          = string.Empty,  // generated fresh at delivery time
                Status               = DispatchStatus.Pending,
                AttemptCount         = 0,
                NextAttemptAt        = DateTime.UtcNow,
                DispatchId           = Guid.NewGuid().ToString("N"),
                CreatedAt            = DateTime.UtcNow
            });
        }
    }

    private static string ComputeFingerprint(string? userAgent, string? ipAddress)
    {
        var subnet = NormalizeSubnet(ipAddress);
        var raw    = $"{userAgent ?? string.Empty}|{subnet}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
    }

    private static string NormalizeSubnet(string? ip)
    {
        if (string.IsNullOrEmpty(ip)) return "unknown";
        var parts = ip.Split('.');
        return parts.Length == 4
            ? $"{parts[0]}.{parts[1]}.{parts[2]}"  // /24 — strips host octet
            : ip;                                    // IPv6 — keep as-is
    }

    private static string GenerateSid()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Tail(string s) => s.Length <= 6 ? s : s[^6..];
}
