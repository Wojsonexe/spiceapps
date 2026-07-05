using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SpiceAuth.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddFederationSessionAndPhase3 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "ConsentVersion",
                table: "oauth_clients",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "FirstParty",
                table: "oauth_clients",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "ConsentVersion",
                table: "consent_grants",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastUsedAt",
                table: "consent_grants",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "client_secrets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientInternalId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    Prefix = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    SecretHash = table.Column<string>(type: "text", nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_client_secrets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_client_secrets_oauth_clients_ClientInternalId",
                        column: x => x.ClientInternalId,
                        principalTable: "oauth_clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "federation_dispatches",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    GlobalSessionId = table.Column<Guid>(type: "uuid", nullable: false),
                    Sid = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    AppName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    BackchannelLogoutUri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    LogoutToken = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    AttemptCount = table.Column<int>(type: "integer", nullable: false),
                    LastAttemptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    NextAttemptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    DeliveredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    DeadLetterAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    DispatchId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_federation_dispatches", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "global_sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Sid = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastActivityAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    IpAddress = table.Column<string>(type: "text", nullable: true),
                    UserAgent = table.Column<string>(type: "text", nullable: true),
                    DeviceFingerprint = table.Column<string>(type: "text", nullable: true),
                    Location = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_global_sessions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "logout_token_jtis",
                columns: table => new
                {
                    Jti = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    UsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_logout_token_jtis", x => x.Jti);
                });

            migrationBuilder.CreateTable(
                name: "replay_cache_entries",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EntryKey = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Bucket = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    RecordedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_replay_cache_entries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Slug = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    DisplayName = table.Column<string>(type: "text", nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tenants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "federation_dispatch_attempts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FederationDispatchId = table.Column<Guid>(type: "uuid", nullable: false),
                    AttemptedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    HttpStatusCode = table.Column<int>(type: "integer", nullable: false),
                    Success = table.Column<bool>(type: "boolean", nullable: false),
                    ErrorMessage = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    DurationMs = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_federation_dispatch_attempts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_federation_dispatch_attempts_federation_dispatches_Federati~",
                        column: x => x.FederationDispatchId,
                        principalTable: "federation_dispatches",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "app_sessions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    GlobalSessionId = table.Column<Guid>(type: "uuid", nullable: false),
                    AppName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    LocalSessionId = table.Column<string>(type: "text", nullable: true),
                    BackchannelLogoutUri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    RegisteredAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_app_sessions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_app_sessions_global_sessions_GlobalSessionId",
                        column: x => x.GlobalSessionId,
                        principalTable: "global_sessions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "tenant_memberships",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TenantId = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    Role = table.Column<string>(type: "text", nullable: false),
                    JoinedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tenant_memberships", x => x.Id);
                    table.ForeignKey(
                        name: "FK_tenant_memberships_tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_signing_keys_IsActive_IsPrimary_ExpiresAt",
                table: "signing_keys",
                columns: new[] { "IsActive", "IsPrimary", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_signing_keys_IsPrimary",
                table: "signing_keys",
                column: "IsPrimary");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_FamilyId",
                table: "refresh_tokens",
                column: "FamilyId");

            migrationBuilder.CreateIndex(
                name: "IX_app_sessions_GlobalSessionId",
                table: "app_sessions",
                column: "GlobalSessionId");

            migrationBuilder.CreateIndex(
                name: "IX_app_sessions_GlobalSessionId_AppName",
                table: "app_sessions",
                columns: new[] { "GlobalSessionId", "AppName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_client_secrets_ClientInternalId_IsActive",
                table: "client_secrets",
                columns: new[] { "ClientInternalId", "IsActive" });

            migrationBuilder.CreateIndex(
                name: "IX_client_secrets_Prefix",
                table: "client_secrets",
                column: "Prefix");

            migrationBuilder.CreateIndex(
                name: "IX_federation_dispatch_attempts_FederationDispatchId",
                table: "federation_dispatch_attempts",
                column: "FederationDispatchId");

            migrationBuilder.CreateIndex(
                name: "IX_federation_dispatches_GlobalSessionId",
                table: "federation_dispatches",
                column: "GlobalSessionId");

            migrationBuilder.CreateIndex(
                name: "IX_federation_dispatches_NextAttemptAt",
                table: "federation_dispatches",
                column: "NextAttemptAt");

            migrationBuilder.CreateIndex(
                name: "IX_federation_dispatches_Status",
                table: "federation_dispatches",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_global_sessions_ExpiresAt",
                table: "global_sessions",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_global_sessions_Sid",
                table: "global_sessions",
                column: "Sid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_global_sessions_UserId",
                table: "global_sessions",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_global_sessions_UserId_RevokedAt",
                table: "global_sessions",
                columns: new[] { "UserId", "RevokedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_logout_token_jtis_UsedAt",
                table: "logout_token_jtis",
                column: "UsedAt");

            migrationBuilder.CreateIndex(
                name: "IX_replay_cache_entries_EntryKey",
                table: "replay_cache_entries",
                column: "EntryKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_replay_cache_entries_ExpiresAt",
                table: "replay_cache_entries",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_tenant_memberships_TenantId_UserId",
                table: "tenant_memberships",
                columns: new[] { "TenantId", "UserId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_tenants_Slug",
                table: "tenants",
                column: "Slug",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "app_sessions");

            migrationBuilder.DropTable(
                name: "client_secrets");

            migrationBuilder.DropTable(
                name: "federation_dispatch_attempts");

            migrationBuilder.DropTable(
                name: "logout_token_jtis");

            migrationBuilder.DropTable(
                name: "replay_cache_entries");

            migrationBuilder.DropTable(
                name: "tenant_memberships");

            migrationBuilder.DropTable(
                name: "global_sessions");

            migrationBuilder.DropTable(
                name: "federation_dispatches");

            migrationBuilder.DropTable(
                name: "tenants");

            migrationBuilder.DropIndex(
                name: "IX_signing_keys_IsActive_IsPrimary_ExpiresAt",
                table: "signing_keys");

            migrationBuilder.DropIndex(
                name: "IX_signing_keys_IsPrimary",
                table: "signing_keys");

            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_FamilyId",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "ConsentVersion",
                table: "oauth_clients");

            migrationBuilder.DropColumn(
                name: "FirstParty",
                table: "oauth_clients");

            migrationBuilder.DropColumn(
                name: "ConsentVersion",
                table: "consent_grants");

            migrationBuilder.DropColumn(
                name: "LastUsedAt",
                table: "consent_grants");
        }
    }
}
