using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.Infrastructure.BackgroundServices;

/// <summary>
/// Durable backchannel logout dispatcher.
/// Picks up Pending/Failed FederationDispatch rows and delivers them with
/// exponential backoff + jitter. Dead-letters after MaxAttempts.
///
/// Guarantees:
/// - At-least-once delivery (rows survive crashes)
/// - Fresh logout_token per attempt (retries never fail due to token expiry)
/// - Idempotent on the receiver side (each token carries a unique JTI)
/// - Graceful shutdown: completes the in-flight batch before stopping
/// </summary>
public sealed class FederationDispatchWorker(
    IServiceScopeFactory scopeFactory,
    IHttpClientFactory httpClientFactory,
    ILogger<FederationDispatchWorker> logger) : BackgroundService
{
    private const int MaxAttempts = 5;
    private const int BatchSize   = 50;
    private static readonly TimeSpan PollingInterval      = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan GracefulShutdownWait = TimeSpan.FromSeconds(30);

    // Exponential backoff delays indexed by AttemptCount (0-based)
    private static readonly TimeSpan[] BackoffDelays =
    [
        TimeSpan.Zero,
        TimeSpan.FromSeconds(30),
        TimeSpan.FromMinutes(2),
        TimeSpan.FromMinutes(10),
        TimeSpan.FromMinutes(30)
    ];

    private Task? _currentBatch;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("FederationDispatchWorker started (poll every {Sec}s)",
            (int)PollingInterval.TotalSeconds);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Track in-flight batch so StopAsync can drain it
                _currentBatch = ProcessBatchAsync(stoppingToken);
                await _currentBatch;
                _currentBatch = null;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex,
                    "FederationDispatchWorker: unhandled error in batch — will retry next poll");
            }

            try
            {
                await Task.Delay(PollingInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }

        logger.LogInformation("FederationDispatchWorker: polling loop exited");
    }

    /// <summary>
    /// On shutdown: allow the current in-flight batch up to GracefulShutdownWait seconds to finish.
    /// This prevents partially-committed dispatch attempts on clean restarts.
    /// </summary>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);

        if (_currentBatch is { IsCompleted: false })
        {
            logger.LogInformation(
                "FederationDispatchWorker: draining in-flight batch (up to {Sec}s)…",
                (int)GracefulShutdownWait.TotalSeconds);

            using var drain = new CancellationTokenSource(GracefulShutdownWait);
            try
            {
                await _currentBatch.WaitAsync(drain.Token);
                logger.LogInformation("FederationDispatchWorker: batch drained cleanly");
            }
            catch (OperationCanceledException)
            {
                logger.LogWarning(
                    "FederationDispatchWorker: drain timeout after {Sec}s — some rows may re-deliver",
                    (int)GracefulShutdownWait.TotalSeconds);
            }
        }

        logger.LogInformation("FederationDispatchWorker stopped");
    }

    private async Task ProcessBatchAsync(CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db           = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenService>();

        var now = DateTime.UtcNow;

        var pending = await db.Set<FederationDispatch>()
            .Where(d =>
                (d.Status == DispatchStatus.Pending || d.Status == DispatchStatus.Failed) &&
                d.NextAttemptAt <= now)
            .OrderBy(d => d.CreatedAt)
            .Take(BatchSize)
            .ToListAsync(ct);

        if (pending.Count == 0) return;

        var http = httpClientFactory.CreateClient("BackchannelLogout");

        foreach (var dispatch in pending)
            await DeliverAsync(db, tokenService, http, dispatch, ct);

        await db.SaveChangesAsync(ct);
    }

    private async Task DeliverAsync(
        ApplicationDbContext db,
        ITokenService tokenService,
        HttpClient http,
        FederationDispatch dispatch,
        CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        int httpStatus = 0;
        string? errorMsg = null;
        bool success = false;

        try
        {
            // Generate a fresh logout token on every attempt so retries don't fail
            // due to the 2-minute token lifetime.
            string logoutToken;
            try
            {
                logoutToken = await tokenService.GenerateLogoutTokenAsync(dispatch.Sid, dispatch.AppName);
            }
            catch (Exception ex)
            {
                sw.Stop();
                RecordAttemptAndScheduleRetry(db, dispatch, 0, false,
                    $"token_gen_failed: {ex.Message}", sw.ElapsedMilliseconds);
                return;
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            var response = await http.PostAsync(
                dispatch.BackchannelLogoutUri,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["logout_token"] = logoutToken
                }),
                cts.Token);

            httpStatus = (int)response.StatusCode;
            success    = response.IsSuccessStatusCode;
            if (!success) errorMsg = $"HTTP {httpStatus}";
        }
        catch (OperationCanceledException)
        {
            errorMsg = "Timeout (5s)";
        }
        catch (Exception ex)
        {
            errorMsg = ex.Message;
        }
        finally
        {
            sw.Stop();
        }

        RecordAttemptAndScheduleRetry(db, dispatch, httpStatus, success, errorMsg, sw.ElapsedMilliseconds);

        if (success)
            logger.LogInformation("Backchannel delivered → {App} attempt {N}",
                dispatch.AppName, dispatch.AttemptCount);
        else if (dispatch.Status == DispatchStatus.DeadLetter)
            logger.LogError("Backchannel DEAD-LETTER → {App} ({Uri}) after {N} attempts: {Err}",
                dispatch.AppName, dispatch.BackchannelLogoutUri, dispatch.AttemptCount, errorMsg);
        else
            logger.LogWarning("Backchannel retry scheduled for {App} (attempt {N}, next {Next}): {Err}",
                dispatch.AppName, dispatch.AttemptCount, dispatch.NextAttemptAt, errorMsg);
    }

    private void RecordAttemptAndScheduleRetry(
        ApplicationDbContext db,
        FederationDispatch dispatch,
        int httpStatus,
        bool success,
        string? errorMsg,
        long durationMs)
    {
        dispatch.AttemptCount++;
        dispatch.LastAttemptAt = DateTime.UtcNow;

        db.Set<FederationDispatchAttempt>().Add(new FederationDispatchAttempt
        {
            FederationDispatchId = dispatch.Id,
            AttemptedAt          = DateTime.UtcNow,
            HttpStatusCode       = httpStatus,
            Success              = success,
            ErrorMessage         = errorMsg,
            DurationMs           = durationMs
        });

        if (success)
        {
            dispatch.Status      = DispatchStatus.Delivered;
            dispatch.DeliveredAt = DateTime.UtcNow;
        }
        else if (dispatch.AttemptCount >= MaxAttempts)
        {
            dispatch.Status       = DispatchStatus.DeadLetter;
            dispatch.DeadLetterAt = DateTime.UtcNow;
        }
        else
        {
            dispatch.Status = DispatchStatus.Failed;
            var baseDelay   = BackoffDelays[Math.Min(dispatch.AttemptCount, BackoffDelays.Length - 1)];
            var jitter      = TimeSpan.FromSeconds(baseDelay.TotalSeconds * 0.1 *
                                                   (Random.Shared.NextDouble() * 2 - 1));
            dispatch.NextAttemptAt = DateTime.UtcNow + baseDelay + jitter;
        }
    }
}
