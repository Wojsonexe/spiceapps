using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Abstractions.Persistence;
using SpiceAuth.Core.Entities.Authorization;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Organization;
using SpiceAuth.Core.Entities.Registration;
using SpiceAuth.Core.Entities.Security;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace SpiceAuth.Infrastructure.Data;

public class ApplicationDbContext
    : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>, IApplicationDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }

    // ── Identity ────────────────────────────────────────────────────────────
    public DbSet<ExternalIdentity> ExternalIdentities => Set<ExternalIdentity>();
    public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();
    public DbSet<EmailVerificationToken> EmailVerificationTokens => Set<EmailVerificationToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();

    // ── Authorization ───────────────────────────────────────────────────────
    public DbSet<Role> SpiceRoles => Set<Role>();
    public DbSet<UserRole> SpiceUserRoles => Set<UserRole>();
    public DbSet<Scope> Scopes => Set<Scope>();
    public DbSet<UserScope> UserScopes => Set<UserScope>();

    // ── OAuth ───────────────────────────────────────────────────────────────
    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<ConsentGrant> ConsentGrants => Set<ConsentGrant>();

    // ── Federation ──────────────────────────────────────────────────────────
    public DbSet<GlobalSession> GlobalSessions => Set<GlobalSession>();
    public DbSet<AppSession> AppSessions => Set<AppSession>();
    public DbSet<FederationDispatch> FederationDispatches => Set<FederationDispatch>();
    public DbSet<FederationDispatchAttempt> FederationDispatchAttempts => Set<FederationDispatchAttempt>();

    // ── OAuth secrets (versioned rotation) ─────────────────────────────────
    public DbSet<ClientSecret> ClientSecrets => Set<ClientSecret>();

    // ── Replay cache (generic, DB-backed) ──────────────────────────────────
    public DbSet<ReplayCacheEntry> ReplayCacheEntries => Set<ReplayCacheEntry>();

    // ── Organization ────────────────────────────────────────────────────────
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationMember> OrganizationMembers => Set<OrganizationMember>();
    public DbSet<OrganizationInvitation> OrganizationInvitations => Set<OrganizationInvitation>();

    // ── Tenant ──────────────────────────────────────────────────────────────
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<TenantMembership> TenantMemberships => Set<TenantMembership>();

    // ── Security ────────────────────────────────────────────────────────────
    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();
    public DbSet<MfaSettings> MfaSettings => Set<MfaSettings>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<LogoutTokenJti> LogoutTokenJtis => Set<LogoutTokenJti>();

    // ── Registration ────────────────────────────────────────────────────────
    public DbSet<RegistrationRequest> RegistrationRequests => Set<RegistrationRequest>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        ConfigureIdentityTables(modelBuilder);
        ConfigureAuthorization(modelBuilder);
        ConfigureOAuth(modelBuilder);
        ConfigureFederation(modelBuilder);
        ConfigureOrganization(modelBuilder);
        ConfigureTenant(modelBuilder);
        ConfigureSecurity(modelBuilder);
        ConfigureIdentityExtensions(modelBuilder);
        ConfigurePhase3Entities(modelBuilder);
        ConfigureIndexes(modelBuilder);
    }

    // ════════════════════════════════════════════════════════════════════════
    // ASP.NET Identity — rename tables to snake_case / clean names
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureIdentityTables(ModelBuilder b)
    {
        b.Entity<ApplicationUser>().ToTable("users");
        b.Entity<IdentityRole<Guid>>().ToTable("asp_roles");
        b.Entity<IdentityUserRole<Guid>>().ToTable("asp_user_roles");
        b.Entity<IdentityUserClaim<Guid>>().ToTable("asp_user_claims");
        b.Entity<IdentityUserLogin<Guid>>().ToTable("asp_user_logins");
        b.Entity<IdentityRoleClaim<Guid>>().ToTable("asp_role_claims");
        b.Entity<IdentityUserToken<Guid>>().ToTable("asp_user_tokens");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Authorization: Role, UserRole, Scope, UserScope
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureAuthorization(ModelBuilder b)
    {
        // ── Role ──────────────────────────────────────────────────────────
        b.Entity<Role>(e =>
        {
            e.ToTable("roles");
            e.HasKey(r => r.Id);
            e.Property(r => r.Name).HasMaxLength(100).IsRequired();
            e.Property(r => r.NormalizedName).HasMaxLength(100).IsRequired();
            e.HasIndex(r => r.NormalizedName).IsUnique();
        });

        // ── UserRole (junction) ───────────────────────────────────────────
        b.Entity<UserRole>(e =>
        {
            e.ToTable("user_roles");
            e.HasKey(ur => new { ur.UserId, ur.RoleId });

            e.HasOne(ur => ur.User)
                .WithMany(u => u.UserRoles)
                .HasForeignKey(ur => ur.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(ur => ur.Role)
                .WithMany(r => r.UserRoles)
                .HasForeignKey(ur => ur.RoleId)
                .OnDelete(DeleteBehavior.Cascade);

            e.Property(ur => ur.AssignedAt)
                .HasDefaultValueSql("NOW()");
        });

        // ── Scope ─────────────────────────────────────────────────────────
        b.Entity<Scope>(e =>
        {
            e.ToTable("scopes");
            e.HasKey(s => s.Id);
            e.Property(s => s.Name).HasMaxLength(200).IsRequired();
            e.HasIndex(s => s.Name).IsUnique();
        });

        // ── UserScope (junction) ──────────────────────────────────────────
        b.Entity<UserScope>(e =>
        {
            e.ToTable("user_scopes");
            e.HasKey(us => new { us.UserId, us.ScopeId });   // ← FIXES THE CRASH

            e.HasOne(us => us.User)
                .WithMany(u => u.UserScopes)
                .HasForeignKey(us => us.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(us => us.Scope)
                .WithMany(s => s.UserScopes)
                .HasForeignKey(us => us.ScopeId)
                .OnDelete(DeleteBehavior.Cascade);

            e.Property(us => us.GrantedAt)
                .HasDefaultValueSql("NOW()");
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // OAuth2 / OIDC
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureOAuth(ModelBuilder b)
    {
        // ── OAuthClient ───────────────────────────────────────────────────
        b.Entity<OAuthClient>(e =>
        {
            e.ToTable("oauth_clients");
            e.HasKey(c => c.Id);
            e.Property(c => c.ClientId).HasMaxLength(200).IsRequired();
            e.Property(c => c.Name).HasMaxLength(200).IsRequired();

            e.HasOne(c => c.Organization)
                .WithMany(o => o.Clients)
                .HasForeignKey(c => c.OrganizationId)
                .OnDelete(DeleteBehavior.SetNull)
                .IsRequired(false);
        });

        // ── AuthorizationCode ─────────────────────────────────────────────
        b.Entity<AuthorizationCode>(e =>
        {
            e.ToTable("authorization_codes");
            e.HasKey(ac => ac.Id);
            e.Property(ac => ac.Code).HasMaxLength(500).IsRequired();

            // Optimistic concurrency — prevents double-redemption.
            // EF generates WHERE IsUsed = @original on UPDATE; if 0 rows, throws DbUpdateConcurrencyException.
            e.Property(ac => ac.IsUsed).IsConcurrencyToken();

            e.HasOne(ac => ac.Client)
                .WithMany(c => c.AuthorizationCodes)
                .HasForeignKey(ac => ac.ClientId)
                .OnDelete(DeleteBehavior.Cascade);

            // Nie ma navigation do User — celowo (code żyje krótko, nie nawigujemy)
        });

        // ── RefreshToken ──────────────────────────────────────────────────
        b.Entity<RefreshToken>(e =>
        {
            e.ToTable("refresh_tokens");
            e.HasKey(rt => rt.Id);

            e.HasOne<ApplicationUser>()
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(rt => rt.Client)
                .WithMany(c => c.RefreshTokens)
                .HasForeignKey(rt => rt.ClientId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(rt => rt.ParentToken)
                .WithMany()
                .HasForeignKey(rt => rt.ParentTokenId)
                .OnDelete(DeleteBehavior.Restrict)   // nie kasujemy chain przy usunięciu parenta
                .IsRequired(false);
        });

        // ── ConsentGrant ──────────────────────────────────────────────────
        b.Entity<ConsentGrant>(e =>
        {
            e.ToTable("consent_grants");
            e.HasKey(cg => cg.Id);

            e.HasOne(cg => cg.Client)
                .WithMany(c => c.ConsentGrants)
                .HasForeignKey(cg => cg.ClientId)
                .OnDelete(DeleteBehavior.Cascade);

            // Unique: jeden consent na parę (User, Client)
            e.HasIndex(cg => new { cg.UserId, cg.ClientId }).IsUnique();
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Federation: GlobalSession + AppSession
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureFederation(ModelBuilder b)
    {
        b.Entity<GlobalSession>(e =>
        {
            e.ToTable("global_sessions");
            e.HasKey(s => s.Id);
            e.Property(s => s.Sid).HasMaxLength(256).IsRequired();
            e.HasIndex(s => s.Sid).IsUnique();
            e.HasIndex(s => s.UserId);
            e.HasIndex(s => s.ExpiresAt);
            e.HasIndex(s => new { s.UserId, s.RevokedAt });
        });

        b.Entity<AppSession>(e =>
        {
            e.ToTable("app_sessions");
            e.HasKey(s => s.Id);
            e.Property(s => s.AppName).HasMaxLength(200).IsRequired();
            e.Property(s => s.BackchannelLogoutUri).HasMaxLength(2048).IsRequired();

            e.HasOne(s => s.GlobalSession)
                .WithMany(g => g.AppSessions)
                .HasForeignKey(s => s.GlobalSessionId)
                .OnDelete(DeleteBehavior.Cascade);

            // Unique: one app can register at most one session per GlobalSession
            e.HasIndex(s => new { s.GlobalSessionId, s.AppName }).IsUnique();
            e.HasIndex(s => s.GlobalSessionId);
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Tenant (multi-tenant foundation — nullable, additive)
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureTenant(ModelBuilder b)
    {
        b.Entity<Tenant>(e =>
        {
            e.ToTable("tenants");
            e.HasKey(t => t.Id);
            e.Property(t => t.Slug).HasMaxLength(100).IsRequired();
            e.HasIndex(t => t.Slug).IsUnique();
        });

        b.Entity<TenantMembership>(e =>
        {
            e.ToTable("tenant_memberships");
            e.HasKey(m => m.Id);
            e.HasIndex(m => new { m.TenantId, m.UserId }).IsUnique();

            e.HasOne(m => m.Tenant)
                .WithMany(t => t.Memberships)
                .HasForeignKey(m => m.TenantId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Organization
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureOrganization(ModelBuilder b)
    {
        b.Entity<Organization>(e =>
        {
            e.ToTable("organizations");
            e.HasKey(o => o.Id);
            e.Property(o => o.Slug).HasMaxLength(100).IsRequired();
            e.HasIndex(o => o.Slug).IsUnique();
        });

        b.Entity<OrganizationMember>(e =>
        {
            e.ToTable("organization_members");
            e.HasKey(om => om.Id);

            // Unique: jeden user per org
            e.HasIndex(om => new { om.OrganizationId, om.UserId }).IsUnique();

            e.HasOne(om => om.Organization)
                .WithMany(o => o.Members)
                .HasForeignKey(om => om.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);

            e.HasOne(om => om.User)
                .WithMany(u => u.OrganizationMemberships)
                .HasForeignKey(om => om.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<OrganizationInvitation>(e =>
        {
            e.ToTable("organization_invitations");
            e.HasKey(oi => oi.Id);

            e.HasOne(oi => oi.Organization)
                .WithMany(o => o.Invitations)
                .HasForeignKey(oi => oi.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Security
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureSecurity(ModelBuilder b)
    {
        // ── MfaSettings — shared PK/FK pattern (1:1) ─────────────────────
        b.Entity<MfaSettings>(e =>
        {
            e.ToTable("mfa_settings");
            e.HasKey(m => m.UserId);                    // PK jest jednocześnie FK

            e.HasOne(m => m.User)
                .WithOne(u => u.MfaSettings)
                .HasForeignKey<MfaSettings>(m => m.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<SigningKey>(e =>
        {
            e.ToTable("signing_keys");
            e.HasKey(sk => sk.Id);
            e.Property(sk => sk.KeyId).HasMaxLength(100).IsRequired();
            e.HasIndex(sk => sk.KeyId).IsUnique();
            // Partial index for fast primary-key lookup (only one row should ever match)
            e.HasIndex(sk => sk.IsPrimary);
            e.HasIndex(sk => new { sk.IsActive, sk.IsPrimary, sk.ExpiresAt });
        });

        b.Entity<AuditLog>(e =>
        {
            e.ToTable("audit_logs");
            e.HasKey(al => al.Id);
            // Brak relacji FK do users — audit log nigdy nie kaskaduje
        });

        b.Entity<SecurityEvent>(e =>
        {
            e.ToTable("security_events");
            e.HasKey(se => se.Id);
        });

        b.Entity<LogoutTokenJti>(e =>
        {
            e.ToTable("logout_token_jtis");
            e.HasKey(j => j.Jti);
            e.Property(j => j.Jti).HasMaxLength(256);
            e.HasIndex(j => j.UsedAt);   // for TTL cleanup
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Identity extensions (ExternalIdentity, tokens, attempts)
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureIdentityExtensions(ModelBuilder b)
    {
        b.Entity<ExternalIdentity>(e =>
        {
            e.ToTable("external_identities");
            e.HasKey(ei => ei.Id);

            e.Property(ei => ei.AvatarUrl).HasMaxLength(500);

            e.HasIndex(ei => new { ei.Provider, ei.ProviderUserId }).IsUnique();

            e.HasOne(ei => ei.User)
                .WithMany(u => u.ExternalIdentities)
                .HasForeignKey(ei => ei.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<LoginAttempt>(e =>
        {
            e.ToTable("login_attempts");
            e.HasKey(la => la.Id);

            // nullable FK — logujemy też próby dla nieistniejących userów
            e.HasOne(la => la.User)
                .WithMany()
                .HasForeignKey(la => la.UserId)
                .OnDelete(DeleteBehavior.SetNull)
                .IsRequired(false);
        });

        b.Entity<EmailVerificationToken>(e =>
        {
            e.ToTable("email_verification_tokens");
            e.HasKey(t => t.Id);

            e.HasOne(t => t.User)
                .WithMany()
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<PasswordResetToken>(e =>
        {
            e.ToTable("password_reset_tokens");
            e.HasKey(t => t.Id);

            e.HasOne(t => t.User)
                .WithMany()
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<RegistrationRequest>(e =>
        {
            e.ToTable("registration_requests");
            e.HasKey(r => r.Id);
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Phase 3: FederationDispatch, ClientSecret, ReplayCacheEntry
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigurePhase3Entities(ModelBuilder b)
    {
        b.Entity<FederationDispatch>(e =>
        {
            e.ToTable("federation_dispatches");
            e.HasKey(d => d.Id);
            e.Property(d => d.Sid).HasMaxLength(256).IsRequired();
            e.Property(d => d.AppName).HasMaxLength(200).IsRequired();
            e.Property(d => d.BackchannelLogoutUri).HasMaxLength(2048).IsRequired();
            e.Property(d => d.DispatchId).HasMaxLength(64).IsRequired();
            e.Property(d => d.Status).HasConversion<int>();
            e.HasIndex(d => d.Status);
            e.HasIndex(d => d.NextAttemptAt);
            e.HasIndex(d => d.GlobalSessionId);

            e.HasMany(d => d.Attempts)
                .WithOne(a => a.Dispatch)
                .HasForeignKey(a => a.FederationDispatchId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<FederationDispatchAttempt>(e =>
        {
            e.ToTable("federation_dispatch_attempts");
            e.HasKey(a => a.Id);
            e.Property(a => a.ErrorMessage).HasMaxLength(1000);
            e.HasIndex(a => a.FederationDispatchId);
        });

        b.Entity<ClientSecret>(e =>
        {
            e.ToTable("client_secrets");
            e.HasKey(s => s.Id);
            e.Property(s => s.Prefix).HasMaxLength(32).IsRequired();
            e.Property(s => s.Name).HasMaxLength(200);

            e.HasOne(s => s.Client)
                .WithMany()
                .HasForeignKey(s => s.ClientInternalId)
                .OnDelete(DeleteBehavior.Cascade);

            // Prefix lookup for fast O(1) auth without loading all secrets
            e.HasIndex(s => s.Prefix);
            e.HasIndex(s => new { s.ClientInternalId, s.IsActive });
        });

        b.Entity<ReplayCacheEntry>(e =>
        {
            e.ToTable("replay_cache_entries");
            e.HasKey(r => r.Id);
            e.Property(r => r.EntryKey).HasMaxLength(512).IsRequired();
            e.Property(r => r.Bucket).HasMaxLength(100).IsRequired();
            e.HasIndex(r => r.EntryKey).IsUnique();
            e.HasIndex(r => r.ExpiresAt);   // cleanup
        });
    }

    // ════════════════════════════════════════════════════════════════════════
    // Indexes — performance dla auth queries
    // ════════════════════════════════════════════════════════════════════════
    private static void ConfigureIndexes(ModelBuilder b)
    {
        // OAuthClient — ClientId jest używany w każdym OAuth request
        b.Entity<OAuthClient>()
            .HasIndex(c => c.ClientId).IsUnique();

        // AuthorizationCode — code lookup przy token exchange
        b.Entity<AuthorizationCode>()
            .HasIndex(ac => ac.Code).IsUnique();
        b.Entity<AuthorizationCode>()
            .HasIndex(ac => ac.ExpiresAt);              // cleanup expired codes

        // RefreshToken — TokenHash lookup + user/client queries
        b.Entity<RefreshToken>()
            .HasIndex(rt => rt.TokenHash);
        b.Entity<RefreshToken>()
            .HasIndex(rt => new { rt.UserId, rt.ClientId });
        b.Entity<RefreshToken>()
            .HasIndex(rt => rt.ExpiresAt);              // cleanup
        // FamilyId — used by RevokeTokenFamilyAsync on reuse detection (security-critical fast path)
        b.Entity<RefreshToken>()
            .HasIndex(rt => rt.FamilyId);

        // LoginAttempt — brute force detection
        b.Entity<LoginAttempt>()
            .HasIndex(la => new { la.Email, la.AttemptedAt });
        b.Entity<LoginAttempt>()
            .HasIndex(la => new { la.IpAddress, la.AttemptedAt });

        // Tokens — lookup by token value
        b.Entity<EmailVerificationToken>()
            .HasIndex(t => t.Token).IsUnique();
        b.Entity<PasswordResetToken>()
            .HasIndex(t => t.Token).IsUnique();

        // AuditLog — queries po userze i czasie
        b.Entity<AuditLog>()
            .HasIndex(al => new { al.UserId, al.Timestamp });
        b.Entity<AuditLog>()
            .HasIndex(al => al.Timestamp);

        // Organization slug — używany w URL
        b.Entity<Organization>()
            .HasIndex(o => o.Slug).IsUnique();

        // OrganizationInvitation — token lookup
        b.Entity<OrganizationInvitation>()
            .HasIndex(oi => oi.Token).IsUnique();
    }
}