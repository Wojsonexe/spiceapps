using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using SpiceAuth.Application.Services.Email;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Application.Services.RateLimit;
using SpiceAuth.Application.Services.Registration;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Infrastructure.Data;
using SpiceAuth.Infrastructure.Services;
using SpiceAuth.Infrastructure.Services.Email;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Enums;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Authorization;
using SpiceAuth.API.Middleware;
using SpiceAuth.API.Services;
using SpiceAuth.Application.Abstractions.Persistence;
using SpiceAuth.Application.Services;
using SpiceAuth.Application.Services.Audit;
using SpiceAuth.Application.Services.Federation;
using SpiceAuth.Infrastructure.BackgroundServices;
using SpiceAuth.API.Metrics;
using Prometheus;

var builder = WebApplication.CreateBuilder(args);

// ════════════════════════════════════════════════════════════════
// 📋 SERILOG CONFIGURATION
// ════════════════════════════════════════════════════════════════

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("Environment", builder.Environment.EnvironmentName)
    .Enrich.WithMachineName()
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
    .WriteTo.File(
        "logs/spiceauth-.txt",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        fileSizeLimitBytes: 10485760,
        rollOnFileSizeLimit: true)
    .CreateLogger();

builder.Host.UseSerilog();
Log.Information("🚀 Starting SpiceAuth API v1.0 in {Environment} mode...",
    builder.Environment.EnvironmentName);

// ════════════════════════════════════════════════════════════════
// 🔐 SMART DATABASE CONFIGURATION
// ════════════════════════════════════════════════════════════════

var postgresConnection = builder.Configuration.GetConnectionString("PostgreSQL");
var usePostgres = !string.IsNullOrWhiteSpace(postgresConnection);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    if (usePostgres)
    {
        options.UseNpgsql(postgresConnection!, npgsqlOptions =>
        {
            npgsqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(10),
                errorCodesToAdd: null);
            npgsqlOptions.CommandTimeout(30);
        });

        Log.Information("📂 Using PostgreSQL database: {Server}",
            ExtractServerFromConnectionString(postgresConnection!));
    }
    else
    {
        var sqliteConnection = builder.Configuration.GetConnectionString("SQLite")
                               ?? "Data Source=spiceauth.db";

        options.UseSqlite(sqliteConnection);
        Log.Information("📂 Using SQLite database: {ConnectionString}", sqliteConnection);
    }

    if (builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging();
        options.EnableDetailedErrors();
    }

    if (!builder.Environment.IsDevelopment())
    {
        options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
    }
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
{
    options.SignIn.RequireConfirmedAccount = !builder.Environment.IsDevelopment();

    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredUniqueChars = 4;

    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddSignInManager()
.AddDefaultTokenProviders();

// ════════════════════════════════════════════════════════════════
// 🔐 DUAL AUTHENTICATION: Cookies (OAuth flow) + JWT (API)
// ════════════════════════════════════════════════════════════════
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name        = "SpiceAuth.Session";
    options.Cookie.HttpOnly    = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite    = SameSiteMode.Lax;
    options.LoginPath  = "/api/oauth/account/login";
    options.LogoutPath = "/api/oauth/account/logout";
    options.ExpireTimeSpan     = TimeSpan.FromHours(8);
    options.SlidingExpiration  = true;
    
    options.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api") ||
            context.Request.Headers["Accept"].ToString().Contains("application/json"))
        {
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        }

        var returnUrl = Uri.EscapeDataString(context.Request.Path + context.Request.QueryString);
        context.Response.Redirect($"/api/oauth/account/login?returnUrl={returnUrl}");
        return Task.CompletedTask;
    };
});

builder.Services.AddAuthentication()
    .AddJwtBearer("Bearer", options =>
    {
        var jwtIssuer = builder.Configuration["Jwt:Issuer"]
                        ?? (builder.Environment.IsDevelopment()
                            ? "http://localhost:5045"
                            : "https://auth.team5883.pl");

        options.MetadataAddress      = $"{jwtIssuer}/.well-known/openid-configuration";
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();

        options.TokenValidationParameters = new()
        {
            ValidateIssuer           = true,
            ValidateAudience         = true,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer              = jwtIssuer,
            ValidAudience            = "spiceapi",
            ClockSkew                = TimeSpan.Zero,
            RequireSignedTokens      = true,
            RequireExpirationTime    = true,
            RoleClaimType            = ClaimTypes.Role,
            NameClaimType            = ClaimTypes.NameIdentifier,
        };

        options.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                if (context.SecurityToken is System.IdentityModel.Tokens.Jwt.JwtSecurityToken token)
                {
                    var jti = token.Claims.FirstOrDefault(c => c.Type == "jti")?.Value;
                    if (!string.IsNullOrEmpty(jti))
                        Log.Debug("🔐 JWT validated: {Jti}", jti);
                }
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Log.Warning("🔒 [JWT-FAIL] Type={ExType} Message={Msg}\n{Stack}",
                    context.Exception.GetType().Name,
                    context.Exception.Message,
                    context.Exception.ToString());
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                Log.Warning("🔒 [JWT-CHALLENGE] Error={Error} ErrorDescription={Desc} AuthenticateFailure={Fail}",
                    context.Error,
                    context.ErrorDescription,
                    context.AuthenticateFailure?.Message);
                return Task.CompletedTask;
            },
            OnMessageReceived = context =>
            {
                var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                if (authHeader?.StartsWith("Bearer ") == true)
                {
                    var raw = authHeader["Bearer ".Length..];
                    Log.Debug("🔑 [JWT-RECV] Token starts with: {Prefix}...", raw[..Math.Min(20, raw.Length)]);
                }
                else
                {
                    Log.Warning("🔑 [JWT-RECV] No Bearer token in Authorization header (value: {H})", authHeader ?? "(empty)");
                }
                return Task.CompletedTask;
            }
        };
    })
    .AddDiscord(options =>
    {
        options.ClientId     = builder.Configuration["Discord:ClientId"]
                               ?? throw new InvalidOperationException("Discord:ClientId not configured");
        options.ClientSecret = builder.Configuration["Discord:ClientSecret"]
                               ?? throw new InvalidOperationException("Discord:ClientSecret not configured");
        options.Scope.Add("identify");
        options.Scope.Add("email");
        options.CallbackPath = "/api/oauth/external/discord/callback";
        options.SaveTokens   = true;
        options.CorrelationCookie.SameSite    = SameSiteMode.Lax;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Events.OnCreatingTicket = ctx =>
        {
            // Map Discord's `verified` boolean as a claim so the callback can enforce email-match rules
            if (ctx.User.TryGetProperty("verified", out var verified)
                && verified.ValueKind == System.Text.Json.JsonValueKind.True)
            {
                ctx.Identity!.AddClaim(
                    new System.Security.Claims.Claim("urn:discord:verified", "true"));
            }

            // Build the full CDN avatar URL from id + avatar hash
            if (ctx.User.TryGetProperty("id", out var discordId) &&
                ctx.User.TryGetProperty("avatar", out var avatarHash) &&
                avatarHash.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                var avatarUrl = $"https://cdn.discordapp.com/avatars/{discordId.GetString()}/{avatarHash.GetString()}.png";
                ctx.Identity!.AddClaim(
                    new System.Security.Claims.Claim("urn:discord:avatar", avatarUrl));
            }

            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.DefaultPolicy = new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes("Bearer", "Identity.Application")
        .RequireAuthenticatedUser()
        .Build();
});

// ════════════════════════════════════════════════════════════════
// 🔒 RATE LIMITING
// ════════════════════════════════════════════════════════════════

builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(options =>
{
    options.EnableEndpointRateLimiting = true;
    options.StackBlockedRequests       = false;
    options.HttpStatusCode             = 429;
    options.RealIpHeader               = "X-Real-IP";
    options.ClientIdHeader             = "X-ClientId";

    options.GeneralRules =
    [
        new() { Endpoint = "POST:/oauth/token",          Period = "1m", Limit = 10  },
        new() { Endpoint = "POST:/oauth/account/login",  Period = "5m", Limit = 5   },
        new() { Endpoint = "POST:/oauth/authorize",      Period = "1m", Limit = 30  },
        new() { Endpoint = "*",                          Period = "1m", Limit = 100 }
    ];
});

builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();
builder.Services.AddInMemoryRateLimiting();

Log.Information("🔒 Rate limiting configured");

// ════════════════════════════════════════════════════════════════
// 🌐 CORS CONFIGURATION
// ════════════════════════════════════════════════════════════════

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowedOrigins", policy =>
    {
        if (builder.Environment.IsDevelopment())
        {
            policy.WithOrigins(
                    "http://localhost:3000",
                    "http://localhost:3001",
                    "http://localhost:3002",
                    "http://localhost:5045",
                    "http://localhost:5001",
                    "http://localhost:5173",
                    "http://localhost:8080")
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials();
        }
        else
        {
            var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins")
                .Get<string[]>() ?? [];

            if (allowedOrigins.Length > 0)
            {
                policy.WithOrigins(allowedOrigins)
                    .WithMethods("GET", "POST", "PUT", "DELETE")
                    .WithHeaders("Authorization", "Content-Type")
                    .AllowCredentials()
                    .SetPreflightMaxAge(TimeSpan.FromHours(1));
            }
            else
            {
                Log.Warning("⚠️ No CORS origins configured for production!");
            }
        }
    });
});

// ════════════════════════════════════════════════════════════════
// 🏥 HEALTH CHECKS
// ════════════════════════════════════════════════════════════════

builder.Services.AddHealthChecks()
    .AddDbContextCheck<ApplicationDbContext>("database");

// ════════════════════════════════════════════════════════════════
// 🔑 DATA PROTECTION — persistent keys survive app restarts
// Without this, OAuth state encrypted during challenge cannot be
// decrypted after a restart, causing "state was missing or invalid".
// ════════════════════════════════════════════════════════════════

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(
        Path.Combine(builder.Environment.ContentRootPath, "dp-keys")))
    .SetApplicationName("SpiceAuth");

// ════════════════════════════════════════════════════════════════
// 📦 DEPENDENCY INJECTION
// ════════════════════════════════════════════════════════════════

builder.Services.AddScoped<DbContext>(provider =>
    provider.GetRequiredService<ApplicationDbContext>());
builder.Services.AddScoped<IIdentityStore, IdentityStore>();

builder.Services.AddScoped<IPasswordHasher<ApplicationUser>, SmartPasswordHasher<ApplicationUser>>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<MfaService>();
builder.Services.AddScoped<IExternalAuthService, ExternalAuthService>();

builder.Services.AddScoped<IIdentityService, IdentityService>();
builder.Services.AddScoped<UserMigrationService>();
builder.Services.AddScoped<IOAuthService, OAuthService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IKeyManagementService, KeyManagementService>();
builder.Services.AddScoped<IRegistrationService, RegistrationService>();
builder.Services.AddScoped<IEmailService, EmailService>();

// ── Federation ────────────────────────────────────────────────────────────────
builder.Services.AddScoped<IApplicationDbContext>(sp =>
    sp.GetRequiredService<ApplicationDbContext>());
builder.Services.AddScoped<IFederationService, FederationService>();

// ── Rate limiting (internal brute-force protection) ────────────────────────
builder.Services.AddSingleton<IRateLimitService, InMemoryRateLimitService>();

// ── Security events (fire-and-forget, non-blocking) ────────────────────────
builder.Services.AddSingleton<ISecurityEventService, SecurityEventService>();

// ── PKCE validation (3A) ───────────────────────────────────────────────────
builder.Services.AddScoped<IPkceService, PkceService>();

// ── Client IP extraction with trusted-proxy CIDR whitelist (3E) ───────────
builder.Services.AddSingleton<IClientIpService, ClientIpService>();

// ── Replay cache — DB-backed, Redis-swappable (3H) ────────────────────────
builder.Services.AddScoped<IReplayCache, DbReplayCache>();

// ── SSRF protection — DNS-resolving URI validator ─────────────────────────
builder.Services.AddSingleton<IDnsResolver, SystemDnsResolver>();
builder.Services.AddScoped<IUriSanitizer, UriSanitizer>();

// ── Location resolver — no-op default, swap for GeoLite2 when needed (3N) ─
builder.Services.AddSingleton<ILocationResolver, NoOpLocationResolver>();

// ── Prometheus metrics ─────────────────────────────────────────────────────
builder.Services.AddSingleton<SpiceAuthMetrics>();

// HttpClient used for backchannel logout dispatch — separate named client so
// timeouts/policies don't interfere with other outbound calls.
builder.Services.AddHttpClient("BackchannelLogout", client =>
{
    client.Timeout = TimeSpan.FromSeconds(10);
    client.DefaultRequestHeaders.Add("User-Agent", "SpiceAuth/1.0 BackchannelLogout");
});

builder.Services.AddHostedService<RateLimitCleanupService>();
builder.Services.AddHostedService<SessionCleanupService>();
builder.Services.AddHostedService<KeyRotationService>();
builder.Services.AddHostedService<FederationDispatchWorker>();

Log.Information("✅ Services registered");

// ════════════════════════════════════════════════════════════════
// 🎛️ CONTROLLERS + ANTIFORGERY + SWAGGER
// ════════════════════════════════════════════════════════════════

builder.Services.AddControllersWithViews()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = 
            JsonNamingPolicy.SnakeCaseLower;
        options.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
    });

builder.Services.AddAntiforgery(options =>
{
    options.HeaderName             = "X-CSRF-TOKEN";
    options.Cookie.Name            = "SpiceAuth.Antiforgery";
    options.Cookie.HttpOnly        = true;
    options.Cookie.SecurePolicy    = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite        = SameSiteMode.Strict;
});

builder.Services.Configure<RouteOptions>(options =>
{
    options.LowercaseUrls          = true;
    options.LowercaseQueryStrings  = false;
});

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title       = "SpiceAuth API",
        Version     = "v1.0",
        Description = "OAuth 2.1 / OIDC Authorization Server — SpiceAuth"
    });

    c.AddSecurityDefinition("Bearer", new()
    {
        Name         = "Authorization",
        Type         = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme       = "Bearer",
        BearerFormat = "JWT",
        In           = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description  = "Enter a valid JWT access token issued by this server"
    });

    c.AddSecurityRequirement(new()
    {
        {
            new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" } },
            Array.Empty<string>()
        }
    });

    // Include XML documentation comments
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
        c.IncludeXmlComments(xmlPath, includeControllerXmlComments: true);

    // Tag grouping — visible in Swagger UI sidebar
    c.TagActionsBy(api => [api.GroupName ?? api.ActionDescriptor.RouteValues["controller"] ?? "Other"]);
    c.DocInclusionPredicate((_, _) => true);
});

var app = builder.Build();

// ════════════════════════════════════════════════════════════════
// 2K — STARTUP VALIDATION
// ════════════════════════════════════════════════════════════════

var issuerConfig = builder.Configuration["Jwt:Issuer"];
if (string.IsNullOrWhiteSpace(issuerConfig))
{
    Log.Warning("⚠️  Jwt:Issuer is not configured — OIDC discovery document will use the incoming request host. Set this in production.");
}
else
{
    Log.Information("📍 OIDC Issuer: {Issuer}", issuerConfig);
}

var discordClientId = builder.Configuration["Discord:ClientId"];
if (string.IsNullOrWhiteSpace(discordClientId))
    Log.Warning("⚠️  Discord:ClientId not configured — external Discord login will fail");

var clockSkew = TimeSpan.Zero;
if (Math.Abs((DateTimeOffset.UtcNow - DateTimeOffset.Now).TotalSeconds) > 30)
    Log.Warning("⚠️  System clock may be drifting — ensure NTP sync is active (detected drift > 30s)");

Log.Information("📋 Config summary: DB={DbType}, Issuer={Issuer}, RateLimit=InMemory",
    string.IsNullOrWhiteSpace(builder.Configuration.GetConnectionString("PostgreSQL")) ? "SQLite" : "PostgreSQL",
    issuerConfig ?? "(request-derived)");

// ════════════════════════════════════════════════════════════════
// 🔐 DATABASE INITIALIZATION + SEEDING
// ════════════════════════════════════════════════════════════════

if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var context     = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

    try
    {
        Log.Information("🔄 Running migrations...");
        await context.Database.MigrateAsync();
        Log.Information("✅ Migrations applied");

        await SeedRolesAsync(roleManager);
        await SeedSuperuserAsync(userManager);
        await SeedTestOAuthClientAsync(context);
        await SeedInternalClientAsync(context);
        await SeedKaczuchaPanelClientAsync(context);
        await SeedSpiceApiWebClientAsync(context);

        var keyService = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();
        await keyService.EnsureBootstrapKeyAsync();
        Log.Information("✅ Signing key initialized");
    }
    catch (Exception ex)
    {
        Log.Fatal(ex, "💥 Database initialization failed");
        throw;
    }
}
else
{
    // ── Production startup validation ─────────────────────────────────────────
    // Verify DB connectivity and signing key existence before accepting traffic.
    using var prodScope = app.Services.CreateScope();
    var prodContext     = prodScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var prodKeyService  = prodScope.ServiceProvider.GetRequiredService<IKeyManagementService>();

    try
    {
        // 1. Database connectivity
        var canConnect = await prodContext.Database.CanConnectAsync();
        if (!canConnect)
            throw new InvalidOperationException("Cannot connect to production database");
        Log.Information("✅ Database connection verified");

        // 2. Pending EF migrations check (warn but don't block — ops may run migrations separately)
        var pending = await prodContext.Database.GetPendingMigrationsAsync();
        var pendingList = pending.ToList();
        if (pendingList.Count > 0)
            Log.Warning("⚠️  {Count} pending database migrations: {Migrations}",
                pendingList.Count, string.Join(", ", pendingList));

        // 3. Signing key existence (fatal if none — server cannot issue tokens)
        await prodKeyService.EnsureBootstrapKeyAsync();
        var primaryKey = await prodKeyService.GetPrimaryKeyAsync();
        var expiresIn  = primaryKey.ExpiresAt - DateTime.UtcNow;
        Log.Information("✅ Primary signing key: {Kid}, expires in {Days:F1} days",
            primaryKey.KeyId, expiresIn.TotalDays);

        if (expiresIn < TimeSpan.FromDays(14))
            Log.Warning("⚠️  Signing key expires in {Days:F1} days — rotation due soon", expiresIn.TotalDays);

        // 4. FamilyId integrity — auto-heal legacy NULL rows before traffic arrives
        // Uses raw SQL because the EF entity uses Guid? and EF won't generate IS NULL queries
        // against a non-nullable column after the NOT NULL migration has run.
        try
        {
            var healed = await prodContext.Database.ExecuteSqlRawAsync(
                "UPDATE refresh_tokens SET \"FamilyId\" = gen_random_uuid() WHERE \"FamilyId\" IS NULL");
            if (healed > 0)
                Log.Warning("⚠️  Auto-healed {Count} refresh_token rows with NULL FamilyId", healed);
            else
                Log.Information("✅ FamilyId integrity: no NULL rows found");
        }
        catch (Exception healEx)
        {
            // Non-fatal — may fail on SQLite (dev) or if column is already NOT NULL
            Log.Warning(healEx, "FamilyId auto-heal skipped (expected on SQLite or after migration)");
        }
    }
    catch (Exception ex)
    {
        Log.Fatal(ex, "💥 Production startup validation failed — aborting");
        throw;
    }
}

// ════════════════════════════════════════════════════════════════
// 🔒 SECURITY MIDDLEWARE PIPELINE
// ════════════════════════════════════════════════════════════════

app.UseMiddleware<CorrelationIdMiddleware>();

app.UseSerilogRequestLogging(options =>
{
    options.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
    {
        diagnosticContext.Set("ClientIP", httpContext.Connection.RemoteIpAddress);
        diagnosticContext.Set("UserAgent", httpContext.Request.Headers["User-Agent"].ToString());
        if (httpContext.Items.TryGetValue("CorrelationId", out var cid))
            diagnosticContext.Set("CorrelationId", cid);
    };
});

app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;

    if (!app.Environment.IsDevelopment())
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";

    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"]        = "DENY";
    headers["X-XSS-Protection"]       = "1; mode=block";
    headers["Referrer-Policy"]        = "strict-origin-when-cross-origin";
    headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';";
    headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=()";
    headers.Remove("Server");
    headers.Remove("X-Powered-By");

    await next();
});

if (!app.Environment.IsDevelopment())
    app.UseHttpsRedirection();

app.UseIpRateLimiting();

// Swagger: enabled in Development; in Production only when SwaggerEnabled=true
var swaggerEnabled = app.Environment.IsDevelopment() ||
    builder.Configuration.GetValue<bool>("Swagger:Enabled");

if (swaggerEnabled)
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SpiceAuth API v1");
        c.RoutePrefix = "swagger";
        c.DisplayRequestDuration();
        c.DefaultModelsExpandDepth(-1);  // collapse schema section by default
    });
}

app.UseCors("AllowedOrigins");
app.UseCookiePolicy(new CookiePolicyOptions
{
    MinimumSameSitePolicy = SameSiteMode.Lax,
    Secure = CookieSecurePolicy.SameAsRequest,
});
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapControllers();

// Prometheus scrape endpoint — allow only from loopback/internal CIDR in production
// Configure nginx/load-balancer to restrict /metrics to your monitoring network
app.MapMetrics("/metrics");

Log.Information("✅ SpiceAuth API started successfully!");
Log.Information("📍 Database: {DbType}", usePostgres ? "PostgreSQL" : "SQLite");
Log.Information("📍 Base URL: {BaseUrl}",
    builder.Configuration["App:BaseUrl"] ?? "http://localhost:5045");

try
{
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "💥 Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

// ════════════════════════════════════════════════════════════════
// 🌱 HELPER METHODS
// ════════════════════════════════════════════════════════════════

static string ExtractServerFromConnectionString(string connectionString)
{
    try
    {
        var parts    = connectionString.Split(';');
        var hostPart = parts.FirstOrDefault(p =>
            p.Trim().StartsWith("Host=",   StringComparison.OrdinalIgnoreCase) ||
            p.Trim().StartsWith("Server=", StringComparison.OrdinalIgnoreCase));

        return hostPart != null ? hostPart.Split('=')[1].Trim() : "Unknown";
    }
    catch { return "Unknown"; }
}

static async Task SeedRolesAsync(RoleManager<IdentityRole<Guid>> roleManager)
{
    string[] roles = ["Admin", "User"];

    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            var result = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            if (result.Succeeded)
                Log.Information("✅ Role created: {Role}", role);
            else
                Log.Error("❌ Failed to create role {Role}: {Errors}", role,
                    string.Join(", ", result.Errors.Select(e => e.Description)));
        }
        else
        {
            Log.Information("ℹ️ Role already exists: {Role}", role);
        }
    }
}

static async Task SeedSuperuserAsync(UserManager<ApplicationUser> userManager)
{
    var superuserEmail = "admin@spiceauth.com";
    var superuser      = await userManager.FindByEmailAsync(superuserEmail);

    if (superuser == null)
    {
        superuser = new ApplicationUser
        {
            Id             = Guid.Parse("719141ef-0968-44a4-8f01-49e26a4d1423"),
            UserName       = "admin",
            Email          = superuserEmail,
            EmailConfirmed = true,
            FirstName      = "Super",
            LastName       = "Admin",
            IsActive       = true,
            SecurityStamp  = Guid.NewGuid().ToString()
        };

        var result = await userManager.CreateAsync(superuser, "Admin@123");

        if (result.Succeeded)
            Log.Information("✅ Superuser created: {Email}", superuserEmail);
        else
        {
            Log.Error("❌ Failed to create superuser: {Errors}",
                string.Join(", ", result.Errors.Select(e => e.Description)));
            return;
        }
    }
    else
    {
        Log.Information("ℹ️ Superuser already exists: {Email}", superuserEmail);
    }

    var roles = await userManager.GetRolesAsync(superuser);
    if (!roles.Contains("Admin"))
    {
        var roleResult = await userManager.AddToRoleAsync(superuser, "Admin");
        if (roleResult.Succeeded)
            Log.Information("✅ Admin role assigned to: {Email}", superuserEmail);
        else
            Log.Error("❌ Failed to assign Admin role: {Errors}",
                string.Join(", ", roleResult.Errors.Select(e => e.Description)));
    }
    else
    {
        Log.Information("ℹ️ Admin role already assigned to: {Email}", superuserEmail);
    }
}

static async Task SeedTestOAuthClientAsync(ApplicationDbContext context)
{
    var testClientId = "testmobileapp";

    if (!await context.OAuthClients.AnyAsync(c => c.ClientId == testClientId))
    {
        var testClient = new OAuthClient
        {
            Id                  = Guid.Parse("2ceb346d-2c9f-4aa8-9a2a-faff375f3f83"),
            ClientId            = testClientId,
            ClientSecretHash    = BCrypt.Net.BCrypt.HashPassword("testsecret123", 13),
            Name                = "Test Mobile App",
            Description         = "Development test client",
            ClientType          = ClientType.Mobile,
            IsActive            = true,
            RequirePkce         = true,
            RequireConsent      = true,
            RedirectUris        = JsonSerializer.Serialize(new[]
            {
                "http://localhost:3000/callback",
                "http://127.0.0.1:3000/callback"
            }),
            AllowedScopes       = JsonSerializer.Serialize(new[] { "openid", "profile", "email" }),
            AllowedGrantTypes   = JsonSerializer.Serialize(new[] { "authorization_code", "refresh_token" }),
            AccessTokenLifetime  = 900,
            RefreshTokenLifetime = 604800,
            CreatedByUserId     = Guid.Parse("719141ef-0968-44a4-8f01-49e26a4d1423"),
            CreatedAt           = DateTime.UtcNow
        };

        context.OAuthClients.Add(testClient);
        await context.SaveChangesAsync();

        Log.Information("✅ Test OAuth client created: {ClientId}", testClientId);
    }
    else
    {
        Log.Information("ℹ️ Test OAuth client already exists: {ClientId}", testClientId);
    }
}

static async Task SeedInternalClientAsync(ApplicationDbContext context)
{
    var clientId = "spiceapi-internal";
    if (!await context.OAuthClients.AnyAsync(c => c.ClientId == clientId))
    {
        context.OAuthClients.Add(new OAuthClient
        {
            Id                   = Guid.NewGuid(),
            ClientId             = clientId,
            ClientSecretHash     = BCrypt.Net.BCrypt.HashPassword("change-in-production", 13),
            Name                 = "SpiceAPI Internal",
            ClientType           = ClientType.Confidential,
            IsActive             = true,
            RequirePkce          = false,
            RequireConsent       = false,
            RedirectUris         = JsonSerializer.Serialize(Array.Empty<string>()),
            AllowedScopes        = JsonSerializer.Serialize(new[] { "openid", "profile", "email" }),
            AllowedGrantTypes    = JsonSerializer.Serialize(new[] { "password", "refresh_token" }),
            AccessTokenLifetime  = 900,
            RefreshTokenLifetime = 604800,
            CreatedByUserId      = Guid.Parse("719141ef-0968-44a4-8f01-49e26a4d1423"),
            CreatedAt            = DateTime.UtcNow
        });
        await context.SaveChangesAsync();
        Log.Information("✅ Internal client created: {ClientId}", clientId);
    }
}

static async Task SeedKaczuchaPanelClientAsync(ApplicationDbContext context)
{
    var clientId = "kaczucha-panel";
    if (!await context.OAuthClients.AnyAsync(c => c.ClientId == clientId))
    {
        context.OAuthClients.Add(new OAuthClient
        {
            Id                   = Guid.NewGuid(),
            ClientId             = clientId,
            ClientSecretHash     = BCrypt.Net.BCrypt.HashPassword("kaczucha-secret-change-me", 13),
            Name                 = "Kaczucha Panel",
            Description          = "Panel zarządzania botem Kaczucha",
            ClientType           = ClientType.Confidential,
            IsActive             = true,
            RequirePkce          = false,
            RequireConsent       = false,
            RedirectUris         = JsonSerializer.Serialize(new[]
            {
                "http://localhost:5001/api/auth/spiceauth/callback"
            }),
            AllowedScopes        = JsonSerializer.Serialize(new[] { "openid", "profile", "email" }),
            AllowedGrantTypes    = JsonSerializer.Serialize(new[] { "authorization_code", "refresh_token" }),
            AccessTokenLifetime  = 900,
            RefreshTokenLifetime = 604800,
            CreatedByUserId      = Guid.Parse("719141ef-0968-44a4-8f01-49e26a4d1423"),
            CreatedAt            = DateTime.UtcNow
        });
        await context.SaveChangesAsync();
        Log.Information("✅ Kaczucha Panel client created: {ClientId}", clientId);
    }
}

static async Task SeedSpiceApiWebClientAsync(ApplicationDbContext context)
{
    var clientId = "spiceapi-web";
    if (!await context.OAuthClients.AnyAsync(c => c.ClientId == clientId))
    {
        context.OAuthClients.Add(new OAuthClient
        {
            Id                   = Guid.Parse("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            ClientId             = clientId,
            ClientSecretHash     = "PUBLIC_CLIENT_NO_SECRET",
            Name                 = "SpiceGears Web App",
            Description          = "Frontend aplikacji SpiceGears",
            ClientType           = ClientType.Public,
            IsActive             = true,
            RequirePkce          = true,
            RequireConsent       = false,
            RedirectUris         = JsonSerializer.Serialize(new[]
            {
                "http://localhost:3000/callback",
                "http://localhost:5173/callback",
                "https://app.team5883.pl/callback"
            }),
            AllowedScopes        = JsonSerializer.Serialize(new[]
            {
                "openid", "profile", "email",
                "spiceapi",
                "spiceapi:admin",
                "spiceapi:kitchen",
                "spiceapi:projects",
                "spiceapi:tasks",
                "spiceapi:files",
                "spiceapi:roles"
            }),
            AllowedGrantTypes    = JsonSerializer.Serialize(new[]
            {
                "authorization_code",
                "refresh_token"
            }),
            AccessTokenLifetime  = 900,
            RefreshTokenLifetime = 604800,
            CreatedByUserId      = Guid.Parse("719141ef-0968-44a4-8f01-49e26a4d1423"),
            CreatedAt            = DateTime.UtcNow
        });

        await context.SaveChangesAsync();
        Log.Information("✅ SpiceAPI Web client created: {ClientId}", clientId);
    }
}