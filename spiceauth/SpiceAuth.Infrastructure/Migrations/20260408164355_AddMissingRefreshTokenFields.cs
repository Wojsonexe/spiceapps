using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SpiceAuth.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddMissingRefreshTokenFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "UpdatedAt",
                table: "signing_keys");

            migrationBuilder.DropColumn(
                name: "UpdatedAt",
                table: "refresh_tokens");

            migrationBuilder.AlterColumn<DateTime>(
                name: "ActivatedAt",
                table: "signing_keys",
                type: "timestamp with time zone",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified),
                oldClrType: typeof(DateTime),
                oldType: "timestamp with time zone",
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DeviceId",
                table: "refresh_tokens",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "FamilyId",
                table: "refresh_tokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ReplacedByTokenId",
                table: "refresh_tokens",
                type: "uuid",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DeviceId",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "FamilyId",
                table: "refresh_tokens");

            migrationBuilder.DropColumn(
                name: "ReplacedByTokenId",
                table: "refresh_tokens");

            migrationBuilder.AlterColumn<DateTime>(
                name: "ActivatedAt",
                table: "signing_keys",
                type: "timestamp with time zone",
                nullable: true,
                oldClrType: typeof(DateTime),
                oldType: "timestamp with time zone");

            migrationBuilder.AddColumn<DateTime>(
                name: "UpdatedAt",
                table: "signing_keys",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "UpdatedAt",
                table: "refresh_tokens",
                type: "timestamp with time zone",
                nullable: true);
        }
    }
}
