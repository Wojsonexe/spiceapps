using Prometheus;

namespace SpiceAuth.API.Metrics;

/// <summary>
/// Central Prometheus metrics registry for SpiceAuth.
/// All counters and histograms are created here and injected as a singleton.
///
/// Naming follows Prometheus conventions: snake_case, unit suffix where applicable.
/// </summary>
public sealed class SpiceAuthMetrics
{
    // ── Token issuance ────────────────────────────────────────────────────────

    /// <summary>Total tokens issued, labelled by grant type (authorization_code | refresh_token | client_credentials).</summary>
    public readonly Counter TokensIssued = Prometheus.Metrics.CreateCounter(
        "spiceauth_tokens_issued_total",
        "Number of access tokens successfully issued",
        new CounterConfiguration { LabelNames = ["grant_type", "client_id"] });

    /// <summary>Token endpoint failures, labelled by error type.</summary>
    public readonly Counter TokenEndpointFailures = Prometheus.Metrics.CreateCounter(
        "spiceauth_token_endpoint_failures_total",
        "Number of failed token endpoint requests",
        new CounterConfiguration { LabelNames = ["error", "grant_type"] });

    // ── Auth security events ──────────────────────────────────────────────────

    /// <summary>Authorization code replay attacks detected (each is a critical event).</summary>
    public readonly Counter AuthCodeReplays = Prometheus.Metrics.CreateCounter(
        "spiceauth_auth_code_replays_total",
        "Number of authorization code replay attempts detected");

    /// <summary>Refresh token reuse attacks detected (each triggers full family revocation).</summary>
    public readonly Counter RefreshTokenReuseAttacks = Prometheus.Metrics.CreateCounter(
        "spiceauth_refresh_token_reuse_attacks_total",
        "Number of refresh token reuse (theft) attacks detected");

    /// <summary>PKCE verification failures.</summary>
    public readonly Counter PkceFailures = Prometheus.Metrics.CreateCounter(
        "spiceauth_pkce_failures_total",
        "Number of PKCE code_verifier validation failures");

    /// <summary>Client authentication failures (wrong secret, revoked secret, etc.).</summary>
    public readonly Counter ClientAuthFailures = Prometheus.Metrics.CreateCounter(
        "spiceauth_client_auth_failures_total",
        "Number of failed client authentication attempts",
        new CounterConfiguration { LabelNames = ["client_id"] });

    // ── Session & login ───────────────────────────────────────────────────────

    /// <summary>Successful user logins.</summary>
    public readonly Counter LoginSuccesses = Prometheus.Metrics.CreateCounter(
        "spiceauth_logins_total",
        "Number of successful user logins");

    /// <summary>Failed login attempts (wrong password, locked account, etc.).</summary>
    public readonly Counter LoginFailures = Prometheus.Metrics.CreateCounter(
        "spiceauth_login_failures_total",
        "Number of failed login attempts",
        new CounterConfiguration { LabelNames = ["reason"] });

    // ── Federation dispatch ────────────────────────────────────────────────────

    /// <summary>Backchannel logout dispatches delivered successfully.</summary>
    public readonly Counter FederationDeliveriesSuccess = Prometheus.Metrics.CreateCounter(
        "spiceauth_federation_deliveries_success_total",
        "Number of successfully delivered backchannel logout notifications",
        new CounterConfiguration { LabelNames = ["app_name"] });

    /// <summary>Backchannel logout dispatches that permanently failed (dead-lettered).</summary>
    public readonly Counter FederationDeliveriesDeadLetter = Prometheus.Metrics.CreateCounter(
        "spiceauth_federation_dead_letters_total",
        "Number of backchannel logout notifications permanently failed (dead-letter)",
        new CounterConfiguration { LabelNames = ["app_name"] });

    /// <summary>HTTP duration of individual backchannel logout delivery attempts (ms).</summary>
    public readonly Histogram FederationDispatchDuration = Prometheus.Metrics.CreateHistogram(
        "spiceauth_federation_dispatch_duration_milliseconds",
        "Duration of backchannel logout HTTP delivery attempts in milliseconds",
        new HistogramConfiguration
        {
            LabelNames = ["app_name", "success"],
            Buckets    = [50, 100, 250, 500, 1000, 2500, 5000]
        });

    /// <summary>Current pending/failed dispatch backlog size (gauge, updated on each worker poll).</summary>
    public readonly Gauge FederationDispatchBacklog = Prometheus.Metrics.CreateGauge(
        "spiceauth_federation_dispatch_backlog",
        "Current number of pending/failed federation dispatch rows awaiting delivery");

    // ── Replay cache ──────────────────────────────────────────────────────────

    /// <summary>Replay cache hits (duplicate detected, request blocked).</summary>
    public readonly Counter ReplayCacheHits = Prometheus.Metrics.CreateCounter(
        "spiceauth_replay_cache_hits_total",
        "Number of replay cache hits (duplicate token/key detected)",
        new CounterConfiguration { LabelNames = ["bucket"] });

    // ── Key management ────────────────────────────────────────────────────────

    /// <summary>JWKS key rotations performed.</summary>
    public readonly Counter KeyRotations = Prometheus.Metrics.CreateCounter(
        "spiceauth_key_rotations_total",
        "Number of JWKS signing key rotations performed");

    // ── HTTP request duration (supplement to built-in ASP.NET metrics) ────────

    /// <summary>Duration of OAuth token endpoint requests in milliseconds.</summary>
    public readonly Histogram TokenEndpointDuration = Prometheus.Metrics.CreateHistogram(
        "spiceauth_token_endpoint_duration_milliseconds",
        "Duration of POST /oauth/token requests in milliseconds",
        new HistogramConfiguration
        {
            LabelNames = ["grant_type", "status"],
            Buckets    = [10, 25, 50, 100, 250, 500, 1000, 2500]
        });
}
