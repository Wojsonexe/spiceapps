using Microsoft.EntityFrameworkCore;
using SpiceAuth.Application.Abstractions.Persistence;
using SpiceAuth.Core.Entities.Authorization;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Organization;
using SpiceAuth.Core.Entities.Registration;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Infrastructure.Data.Configurations;

namespace SpiceAuth.Infrastructure.Data;

public class ApplicationDbContext  : DbContext, IApplicationDbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
    
    // DbSets
    public DbSet<User> Users => Set<User>();
    public DbSet<ExternalIdentity> ExternalIdentities => Set<ExternalIdentity>();
    public DbSet<RegistrationRequest> RegistrationRequests => Set<RegistrationRequest>();
    public DbSet<OAuthClient> OAuthClients => Set<OAuthClient>();
    public DbSet<AuthorizationCode> AuthorizationCodes => Set<AuthorizationCode>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<ConsentGrant> ConsentGrants => Set<ConsentGrant>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Scope> Scopes => Set<Scope>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<UserScope> UserScopes => Set<UserScope>();
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationMember> OrganizationMembers => Set<OrganizationMember>();
    public DbSet<OrganizationInvitation> OrganizationInvitations => Set<OrganizationInvitation>();
    public DbSet<MfaSettings> MfaSettings => Set<MfaSettings>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();
    public DbSet<EmailVerificationToken> EmailVerificationTokens => Set<EmailVerificationToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();


    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply all configurations from assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
        modelBuilder.ApplyConfiguration(new EmailVerificationTokenConfiguration());
        modelBuilder.ApplyConfiguration(new PasswordResetTokenConfiguration());
        modelBuilder.ApplyConfiguration(new LoginAttemptConfiguration());
    }
}