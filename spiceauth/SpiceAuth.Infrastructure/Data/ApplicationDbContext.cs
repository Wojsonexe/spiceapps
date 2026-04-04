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

namespace SpiceAuth.Infrastructure.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>, IApplicationDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
    
    // ════════════════════════════════════════════════════════════════
    // IDENTITY & USERS
    // ════════════════════════════════════════════════════════════════
    
    public DbSet<ApplicationUser> ApplicationUsers => Set<ApplicationUser>();
    
    public DbSet<ExternalIdentity> ExternalIdentities => Set<ExternalIdentity>();
    public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();
    
    // ════════════════════════════════════════════════════════════════
    // AUTHORIZATION
    // ════════════════════════════════════════════════════════════════
    
    public DbSet<Role> SpiceRoles => Set<Role>();
    public DbSet<Scope> Scopes => Set<Scope>();
    
    public DbSet<UserRole> SpiceUserRoles => Set<UserRole>();
    public DbSet<UserScope> UserScopes => Set<UserScope>();
    
    // ════════════════════════════════════════════════════════════════
    // OAUTH 2.1 + OIDC
    // ════════════════════════════════════════════════════════════════
    
    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<ConsentGrant> ConsentGrants => Set<ConsentGrant>();
    
    // ════════════════════════════════════════════════════════════════
    // ORGANIZATIONS
    // ════════════════════════════════════════════════════════════════
    
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationMember> OrganizationMembers => Set<OrganizationMember>();
    public DbSet<OrganizationInvitation> OrganizationInvitations => Set<OrganizationInvitation>();
    
    // ════════════════════════════════════════════════════════════════
    // SECURITY
    // ════════════════════════════════════════════════════════════════
    
    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();
    public DbSet<MfaSettings> MfaSettings => Set<MfaSettings>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    
    // ════════════════════════════════════════════════════════════════
    // TOKENS
    // ════════════════════════════════════════════════════════════════
    
    public DbSet<EmailVerificationToken> EmailVerificationTokens => Set<EmailVerificationToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    
    // ════════════════════════════════════════════════════════════════
    // REGISTRATION
    // ════════════════════════════════════════════════════════════════
    
    public DbSet<RegistrationRequest> RegistrationRequests => Set<RegistrationRequest>();

    // ════════════════════════════════════════════════════════════════
    // MODEL CONFIGURATION
    // ════════════════════════════════════════════════════════════════

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply configurations
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

        ConfigureIdentityTables(modelBuilder);
        ConfigureIndexes(modelBuilder);
    }

    private static void ConfigureIdentityTables(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("AspNetUsers");
        });

        modelBuilder.Entity<IdentityRole<Guid>>(entity =>
        {
            entity.ToTable("AspNetRoles");
        });

        modelBuilder.Entity<IdentityUserRole<Guid>>(entity =>
        {
            entity.ToTable("AspNetUserRoles");
        });

        modelBuilder.Entity<IdentityUserClaim<Guid>>(entity =>
        {
            entity.ToTable("AspNetUserClaims");
        });

        modelBuilder.Entity<IdentityUserLogin<Guid>>(entity =>
        {
            entity.ToTable("AspNetUserLogins");
        });

        modelBuilder.Entity<IdentityRoleClaim<Guid>>(entity =>
        {
            entity.ToTable("AspNetRoleClaims");
        });

        modelBuilder.Entity<IdentityUserToken<Guid>>(entity =>
        {
            entity.ToTable("AspNetUserTokens");
        });
    }

    private static void ConfigureIndexes(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<OAuthClient>()
            .HasIndex(c => c.ClientId)
            .IsUnique();

        modelBuilder.Entity<AuthorizationCode>()
            .HasIndex(ac => ac.Code)
            .IsUnique();

        modelBuilder.Entity<RefreshToken>()
            .HasIndex(rt => rt.TokenHash);

        modelBuilder.Entity<RefreshToken>()
            .HasIndex(rt => new { rt.UserId, rt.ClientId });

        modelBuilder.Entity<LoginAttempt>()
            .HasIndex(la => new { la.Email, la.AttemptedAt });

        modelBuilder.Entity<EmailVerificationToken>()
            .HasIndex(evt => evt.Token)
            .IsUnique();

        modelBuilder.Entity<PasswordResetToken>()
            .HasIndex(prt => prt.Token)
            .IsUnique();

        modelBuilder.Entity<AuditLog>()
            .HasIndex(al => new { al.UserId, al.Timestamp });

        modelBuilder.Entity<AuditLog>()
            .HasIndex(al => al.Timestamp);
    }
}
