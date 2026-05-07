using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.Authorization;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Core.Entities.Organization;
using SpiceAuth.Core.Entities.Registration;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Application.Abstractions.Persistence;

public interface IApplicationDbContext
{
    DbSet<ExternalIdentity> ExternalIdentities { get; }
    DbSet<LoginAttempt> LoginAttempts { get; }

    DbSet<Role> SpiceRoles { get; }
    DbSet<Scope> Scopes { get; }
    DbSet<UserRole> SpiceUserRoles { get; }
    DbSet<UserScope> UserScopes { get; }

    DbSet<OAuthClient> OAuthClients { get; }
    DbSet<AuthorizationCode> AuthorizationCodes { get; }
    DbSet<RefreshToken> RefreshTokens { get; }
    DbSet<ConsentGrant> ConsentGrants { get; }

    // ── Federation ─────────────────────────────────────────────────────────────
    DbSet<GlobalSession> GlobalSessions { get; }
    DbSet<AppSession> AppSessions { get; }
    DbSet<FederationDispatch> FederationDispatches { get; }

    // ── OAuth secrets ───────────────────────────────────────────────────────────
    DbSet<ClientSecret> ClientSecrets { get; }

    // ── Organization ────────────────────────────────────────────────────────────
    DbSet<Organization> Organizations { get; }
    DbSet<OrganizationMember> OrganizationMembers { get; }
    DbSet<OrganizationInvitation> OrganizationInvitations { get; }

    // ── Tenant (multi-tenant foundation) ───────────────────────────────────────
    DbSet<Tenant> Tenants { get; }
    DbSet<TenantMembership> TenantMemberships { get; }

    DbSet<SigningKey> SigningKeys { get; }
    DbSet<MfaSettings> MfaSettings { get; }
    DbSet<AuditLog> AuditLogs { get; }
    DbSet<SecurityEvent> SecurityEvents { get; }
    DbSet<LogoutTokenJti> LogoutTokenJtis { get; }

    DbSet<EmailVerificationToken> EmailVerificationTokens { get; }
    DbSet<PasswordResetToken> PasswordResetTokens { get; }

    DbSet<RegistrationRequest> RegistrationRequests { get; }

    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}