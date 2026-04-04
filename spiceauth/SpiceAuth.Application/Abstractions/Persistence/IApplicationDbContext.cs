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
    
    DbSet<Organization> Organizations { get; }
    DbSet<OrganizationMember> OrganizationMembers { get; }
    DbSet<OrganizationInvitation> OrganizationInvitations { get; } 
    
    DbSet<SigningKey> SigningKeys { get; }
    DbSet<MfaSettings> MfaSettings { get; }
    DbSet<AuditLog> AuditLogs { get; }
    DbSet<SecurityEvent> SecurityEvents { get; }
    
    DbSet<EmailVerificationToken> EmailVerificationTokens { get; }
    DbSet<PasswordResetToken> PasswordResetTokens { get; }
    
    DbSet<RegistrationRequest> RegistrationRequests { get; }
    
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}