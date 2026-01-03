using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SpiceAuth.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "OAuthClients",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ClientId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    ClientSecretHash = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ClientType = table.Column<int>(type: "INTEGER", nullable: false),
                    RedirectUris = table.Column<string>(type: "jsonb", nullable: false),
                    PostLogoutRedirectUris = table.Column<string>(type: "jsonb", nullable: false),
                    AllowedScopes = table.Column<string>(type: "jsonb", nullable: false),
                    AllowedGrantTypes = table.Column<string>(type: "jsonb", nullable: false),
                    RequireConsent = table.Column<bool>(type: "INTEGER", nullable: false),
                    RequirePkce = table.Column<bool>(type: "INTEGER", nullable: false),
                    AccessTokenLifetime = table.Column<int>(type: "INTEGER", nullable: false),
                    RefreshTokenLifetime = table.Column<int>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OAuthClients", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "RegistrationRequests",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    FirstName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    LastName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    RequestedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ProcessedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ProcessedByUserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    RejectionReason = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    ExternalProvider = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ExternalProviderId = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Notes = table.Column<string>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RegistrationRequests", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    IsSystemRole = table.Column<bool>(type: "INTEGER", nullable: false),
                    Permissions = table.Column<string>(type: "jsonb", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Scopes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    DisplayName = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Category = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    IsSystemScope = table.Column<bool>(type: "INTEGER", nullable: false),
                    RequiresConsent = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Scopes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SigningKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    KeyId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Algorithm = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    PublicKey = table.Column<string>(type: "text", nullable: false),
                    PrivateKey = table.Column<string>(type: "text", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    ActivatedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    RetiredAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningKeys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    EmailConfirmed = table.Column<bool>(type: "INTEGER", nullable: false),
                    Username = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    PasswordHash = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    FirstName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    LastName = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    ProfilePictureUrl = table.Column<string>(type: "TEXT", nullable: true),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsSuspended = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuspendedUntil = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastLoginAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "AuthorizationCodes",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Code = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ClientId = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RedirectUri = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Scope = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    CodeChallenge = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    CodeChallengeMethod = table.Column<string>(type: "TEXT", maxLength: 10, nullable: true),
                    Nonce = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    IsUsed = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuthorizationCodes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuthorizationCodes_OAuthClients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "OAuthClients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ConsentGrants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ClientId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Scope = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    GrantedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    IsRevoked = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConsentGrants", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ConsentGrants_OAuthClients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "OAuthClients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ClientId = table.Column<Guid>(type: "TEXT", nullable: true),
                    OrganizationId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Action = table.Column<int>(type: "INTEGER", nullable: false),
                    ResourceType = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    ResourceId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    IpAddress = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    UserAgent = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Success = table.Column<bool>(type: "INTEGER", nullable: false),
                    FailureReason = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    Metadata = table.Column<string>(type: "jsonb", nullable: true),
                    Timestamp = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AuditLogs_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "ExternalIdentities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Provider = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    ProviderUserId = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ProviderUsername = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    ProviderEmail = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    AccessToken = table.Column<string>(type: "TEXT", nullable: true),
                    RefreshToken = table.Column<string>(type: "TEXT", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LinkedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ExternalIdentities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ExternalIdentities_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MfaSettings",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    TotpSecret = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    BackupCodes = table.Column<string>(type: "jsonb", nullable: true),
                    EnabledAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastUsedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MfaSettings", x => x.UserId);
                    table.ForeignKey(
                        name: "FK_MfaSettings_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Organizations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Slug = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    LogoUrl = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    OwnerId = table.Column<Guid>(type: "TEXT", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    Settings = table.Column<string>(type: "jsonb", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Organizations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Organizations_Users_OwnerId",
                        column: x => x.OwnerId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "RefreshTokens",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    TokenHash = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ClientId = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Scope = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    IsRevoked = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsUsed = table.Column<bool>(type: "INTEGER", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ParentTokenId = table.Column<Guid>(type: "TEXT", nullable: true),
                    OrganizationId = table.Column<Guid>(type: "TEXT", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_OAuthClients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "OAuthClients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_RefreshTokens_ParentTokenId",
                        column: x => x.ParentTokenId,
                        principalTable: "RefreshTokens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_RefreshTokens_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SecurityEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    EventType = table.Column<int>(type: "INTEGER", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    Description = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    IpAddress = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    Resolved = table.Column<bool>(type: "INTEGER", nullable: false),
                    ResolvedByUserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    Timestamp = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SecurityEvents_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserRoles",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    RoleId = table.Column<Guid>(type: "TEXT", nullable: false),
                    AssignedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRoles", x => new { x.UserId, x.RoleId });
                    table.ForeignKey(
                        name: "FK_UserRoles_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRoles_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserScopes",
                columns: table => new
                {
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    ScopeId = table.Column<Guid>(type: "TEXT", nullable: false),
                    GrantedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    GrantedByUserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserScopes", x => new { x.UserId, x.ScopeId });
                    table.ForeignKey(
                        name: "FK_UserScopes_Scopes_ScopeId",
                        column: x => x.ScopeId,
                        principalTable: "Scopes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserScopes_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "OrganizationInvitations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Role = table.Column<int>(type: "INTEGER", nullable: false),
                    InvitedByUserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Token = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AcceptedAt = table.Column<DateTime>(type: "TEXT", nullable: true),
                    IsRevoked = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OrganizationInvitations", x => x.Id);
                    table.ForeignKey(
                        name: "FK_OrganizationInvitations_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_OrganizationInvitations_Users_InvitedByUserId",
                        column: x => x.InvitedByUserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "OrganizationMembers",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    OrganizationId = table.Column<Guid>(type: "TEXT", nullable: false),
                    UserId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Role = table.Column<int>(type: "INTEGER", nullable: false),
                    JoinedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    InvitedByUserId = table.Column<Guid>(type: "TEXT", nullable: true),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OrganizationMembers", x => x.Id);
                    table.ForeignKey(
                        name: "FK_OrganizationMembers_Organizations_OrganizationId",
                        column: x => x.OrganizationId,
                        principalTable: "Organizations",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_OrganizationMembers_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_Action",
                table: "AuditLogs",
                column: "Action");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_Action_Timestamp",
                table: "AuditLogs",
                columns: new[] { "Action", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_ClientId",
                table: "AuditLogs",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_OrganizationId",
                table: "AuditLogs",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_Success",
                table: "AuditLogs",
                column: "Success");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_Timestamp",
                table: "AuditLogs",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_UserId",
                table: "AuditLogs",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_UserId_Timestamp",
                table: "AuditLogs",
                columns: new[] { "UserId", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_ClientId_UserId",
                table: "AuthorizationCodes",
                columns: new[] { "ClientId", "UserId" });

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_Code",
                table: "AuthorizationCodes",
                column: "Code",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuthorizationCodes_ExpiresAt",
                table: "AuthorizationCodes",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_ConsentGrants_ClientId",
                table: "ConsentGrants",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_ConsentGrants_ExpiresAt",
                table: "ConsentGrants",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_ConsentGrants_IsRevoked",
                table: "ConsentGrants",
                column: "IsRevoked");

            migrationBuilder.CreateIndex(
                name: "IX_ConsentGrants_UserId_ClientId",
                table: "ConsentGrants",
                columns: new[] { "UserId", "ClientId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ExternalIdentities_Provider_ProviderUserId",
                table: "ExternalIdentities",
                columns: new[] { "Provider", "ProviderUserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ExternalIdentities_UserId",
                table: "ExternalIdentities",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_MfaSettings_IsEnabled",
                table: "MfaSettings",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_OAuthClients_ClientId",
                table: "OAuthClients",
                column: "ClientId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OAuthClients_CreatedByUserId",
                table: "OAuthClients",
                column: "CreatedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_OAuthClients_IsActive",
                table: "OAuthClients",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_OAuthClients_OrganizationId",
                table: "OAuthClients",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationInvitations_Email",
                table: "OrganizationInvitations",
                column: "Email");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationInvitations_ExpiresAt",
                table: "OrganizationInvitations",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationInvitations_InvitedByUserId",
                table: "OrganizationInvitations",
                column: "InvitedByUserId");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationInvitations_IsRevoked",
                table: "OrganizationInvitations",
                column: "IsRevoked");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationInvitations_OrganizationId",
                table: "OrganizationInvitations",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationInvitations_Token",
                table: "OrganizationInvitations",
                column: "Token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationMembers_IsActive",
                table: "OrganizationMembers",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationMembers_OrganizationId",
                table: "OrganizationMembers",
                column: "OrganizationId");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationMembers_OrganizationId_UserId",
                table: "OrganizationMembers",
                columns: new[] { "OrganizationId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationMembers_Role",
                table: "OrganizationMembers",
                column: "Role");

            migrationBuilder.CreateIndex(
                name: "IX_OrganizationMembers_UserId",
                table: "OrganizationMembers",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Organizations_IsActive",
                table: "Organizations",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_Organizations_Name",
                table: "Organizations",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Organizations_OwnerId",
                table: "Organizations",
                column: "OwnerId");

            migrationBuilder.CreateIndex(
                name: "IX_Organizations_Slug",
                table: "Organizations",
                column: "Slug",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_ClientId",
                table: "RefreshTokens",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_ExpiresAt",
                table: "RefreshTokens",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_IsRevoked",
                table: "RefreshTokens",
                column: "IsRevoked");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_ParentTokenId",
                table: "RefreshTokens",
                column: "ParentTokenId");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_TokenHash",
                table: "RefreshTokens",
                column: "TokenHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RefreshTokens_UserId_ClientId",
                table: "RefreshTokens",
                columns: new[] { "UserId", "ClientId" });

            migrationBuilder.CreateIndex(
                name: "IX_RegistrationRequests_Email",
                table: "RegistrationRequests",
                column: "Email");

            migrationBuilder.CreateIndex(
                name: "IX_RegistrationRequests_RequestedAt",
                table: "RegistrationRequests",
                column: "RequestedAt");

            migrationBuilder.CreateIndex(
                name: "IX_RegistrationRequests_Status",
                table: "RegistrationRequests",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_IsSystemRole",
                table: "Roles",
                column: "IsSystemRole");

            migrationBuilder.CreateIndex(
                name: "IX_Roles_Name",
                table: "Roles",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Scopes_Category",
                table: "Scopes",
                column: "Category");

            migrationBuilder.CreateIndex(
                name: "IX_Scopes_IsSystemScope",
                table: "Scopes",
                column: "IsSystemScope");

            migrationBuilder.CreateIndex(
                name: "IX_Scopes_Name",
                table: "Scopes",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_EventType",
                table: "SecurityEvents",
                column: "EventType");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_Resolved",
                table: "SecurityEvents",
                column: "Resolved");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_Resolved_Severity_Timestamp",
                table: "SecurityEvents",
                columns: new[] { "Resolved", "Severity", "Timestamp" });

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_Severity",
                table: "SecurityEvents",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_Timestamp",
                table: "SecurityEvents",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityEvents_UserId",
                table: "SecurityEvents",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_SigningKeys_ExpiresAt",
                table: "SigningKeys",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_SigningKeys_IsActive",
                table: "SigningKeys",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_SigningKeys_KeyId",
                table: "SigningKeys",
                column: "KeyId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_AssignedAt",
                table: "UserRoles",
                column: "AssignedAt");

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_RoleId",
                table: "UserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_UserId",
                table: "UserRoles",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_CreatedAt",
                table: "Users",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_IsActive",
                table: "Users",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Username",
                table: "Users",
                column: "Username",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserScopes_ExpiresAt",
                table: "UserScopes",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_UserScopes_GrantedAt",
                table: "UserScopes",
                column: "GrantedAt");

            migrationBuilder.CreateIndex(
                name: "IX_UserScopes_ScopeId",
                table: "UserScopes",
                column: "ScopeId");

            migrationBuilder.CreateIndex(
                name: "IX_UserScopes_UserId",
                table: "UserScopes",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "AuthorizationCodes");

            migrationBuilder.DropTable(
                name: "ConsentGrants");

            migrationBuilder.DropTable(
                name: "ExternalIdentities");

            migrationBuilder.DropTable(
                name: "MfaSettings");

            migrationBuilder.DropTable(
                name: "OrganizationInvitations");

            migrationBuilder.DropTable(
                name: "OrganizationMembers");

            migrationBuilder.DropTable(
                name: "RefreshTokens");

            migrationBuilder.DropTable(
                name: "RegistrationRequests");

            migrationBuilder.DropTable(
                name: "SecurityEvents");

            migrationBuilder.DropTable(
                name: "SigningKeys");

            migrationBuilder.DropTable(
                name: "UserRoles");

            migrationBuilder.DropTable(
                name: "UserScopes");

            migrationBuilder.DropTable(
                name: "Organizations");

            migrationBuilder.DropTable(
                name: "OAuthClients");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "Scopes");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}
