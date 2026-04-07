// SpiceAuth.API/Services/UserMigrationService.cs

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.Identity;
using SpiceAuth.Infrastructure.Data;

namespace SpiceAuth.API.Services;

public class UserMigrationService
{
    private readonly ApplicationDbContext _spiceAuth;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<UserMigrationService> _logger;

    private readonly string _spiceApiConnectionString;

    public UserMigrationService(
        ApplicationDbContext spiceAuth,
        UserManager<ApplicationUser> userManager,
        ILogger<UserMigrationService> logger,
        IConfiguration configuration)
    {
        _spiceAuth  = spiceAuth;
        _userManager = userManager;
        _logger      = logger;
        _spiceApiConnectionString = configuration["Migration:SpiceApiConnectionString"]
            ?? throw new InvalidOperationException(
                "Migration:SpiceApiConnectionString not configured");
    }

    public async Task<MigrationReport> MigrateAsync()
    {
        var report = new MigrationReport();
        var spiceApiUsers = await LoadSpiceApiUsersAsync();

        _logger.LogInformation("Starting migration of {Count} users", spiceApiUsers.Count);

        foreach (var src in spiceApiUsers)
        {
            try
            {
                var existing = await _userManager.FindByEmailAsync(src.Email);
                if (existing != null)
                {
                    _logger.LogInformation("Skipping existing user: {Email}", src.Email);
                    report.Skipped++;
                    continue;
                }

                var username = await GenerateUniqueUsernameAsync(src.Email);

                var appUser = new ApplicationUser
                {
                    Id             = src.Id,           
                    Email          = src.Email.ToLower(),
                    NormalizedEmail = src.Email.ToUpper(),
                    UserName       = username,
                    NormalizedUserName = username.ToUpper(),
                    FirstName      = src.FirstName,
                    LastName       = src.LastName,
                    PasswordHash   = src.PasswordHash,
                    Department     = src.Department,
                    BirthDay       = src.BirthDay,
                    IsApproved     = src.IsApproved,
                    IsActive       = src.IsApproved,   
                    IsSuspended    = false,
                    EmailConfirmed = true,             
                    CreatedAt      = src.CreatedAt,
                    LastLoginAt    = src.LastLogin,
                    SecurityStamp  = Guid.NewGuid().ToString(),
                    ConcurrencyStamp = Guid.NewGuid().ToString(),
                };
                
                var result = await _userManager.CreateAsync(appUser);

                if (!result.Succeeded)
                {
                    var errors = string.Join(", ",
                        result.Errors.Select(e => e.Description));
                    _logger.LogError(
                        "Failed to create user {Email}: {Errors}", src.Email, errors);
                    report.Failed++;
                    report.Errors.Add($"{src.Email}: {errors}");
                    continue;
                }

                if (src.IsAdmin)
                    await _userManager.AddToRoleAsync(appUser, "Admin");
                else
                    await _userManager.AddToRoleAsync(appUser, "User");

                _logger.LogInformation(
                    "Migrated user: {Email} (Id={Id})", src.Email, src.Id);
                report.Migrated++;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception migrating user {Email}", src.Email);
                report.Failed++;
                report.Errors.Add($"{src.Email}: {ex.Message}");
            }
        }

        _logger.LogInformation(
            "Migration complete: {Migrated} migrated, {Skipped} skipped, {Failed} failed",
            report.Migrated, report.Skipped, report.Failed);

        return report;
    }

    private async Task<List<SpiceApiUserDto>> LoadSpiceApiUsersAsync()
    {
        var users = new List<SpiceApiUserDto>();

        await using var conn = new Npgsql.NpgsqlConnection(_spiceApiConnectionString);
        await conn.OpenAsync();

        // Pobierz userów
        var userCmd = new Npgsql.NpgsqlCommand(@"
            SELECT 
                u.""Id"", u.""FirstName"", u.""LastName"", u.""Email"",
                u.""Password"", u.""Department"", u.""BirthDay"",
                u.""IsApproved"", u.""CreatedAt"", u.""LastLogin"", u.""Coin""
            FROM ""Users"" u", conn);

        await using var userReader = await userCmd.ExecuteReaderAsync();
        while (await userReader.ReadAsync())
        {
            users.Add(new SpiceApiUserDto
            {
                Id           = userReader.GetGuid(0),
                FirstName    = userReader.GetString(1),
                LastName     = userReader.GetString(2),
                Email        = userReader.GetString(3),
                PasswordHash = userReader.GetString(4),
                Department   = userReader.GetInt32(5),
                BirthDay     = DateOnly.FromDateTime(
                    userReader.GetFieldValue<DateOnly>(6).ToDateTime(TimeOnly.MinValue)),
                IsApproved   = userReader.GetBoolean(7),
                CreatedAt    = DateTime.SpecifyKind(userReader.GetDateTime(8), DateTimeKind.Utc),
                LastLogin    = DateTime.SpecifyKind(userReader.GetDateTime(9), DateTimeKind.Utc),
                Coin         = userReader.GetDecimal(10),
            });
        }
        await userReader.CloseAsync();

        var roleCmd = new Npgsql.NpgsqlCommand(@"
            SELECT ur.""UsersId"", r.""Scopes""
            FROM ""RoleUser"" ur
            JOIN ""Roles"" r ON r.""RoleId"" = ur.""RolesRoleId""", conn);

        await using var roleReader = await roleCmd.ExecuteReaderAsync();
        var adminUsers = new HashSet<Guid>();

        while (await roleReader.ReadAsync())
        {
            var userId = roleReader.GetGuid(0);
            var scopesJson = roleReader.GetString(1);
            var scopes = System.Text.Json.JsonSerializer
                .Deserialize<List<string>>(scopesJson) ?? new();

            if (scopes.Contains("admin"))
                adminUsers.Add(userId);
        }

        foreach (var u in users)
            u.IsAdmin = adminUsers.Contains(u.Id);

        return users;
    }

    private async Task<string> GenerateUniqueUsernameAsync(string email)
    {
        var _base = email.Split('@')[0]
            .Replace(".", "_")
            .Replace("-", "_")
            .ToLower();

        var username = _base;
        var counter  = 1;

        while (await _spiceAuth.Users.AnyAsync(
                   u => u.NormalizedUserName == username.ToUpper()))
        {
            username = $"{_base}{counter++}";
        }

        return username;
    }
}

public class SpiceApiUserDto
{
    public Guid     Id           { get; set; }
    public string   FirstName    { get; set; } = string.Empty;
    public string   LastName     { get; set; } = string.Empty;
    public string   Email        { get; set; } = string.Empty;
    public string   PasswordHash { get; set; } = string.Empty;
    public int      Department   { get; set; }
    public DateOnly BirthDay     { get; set; }
    public bool     IsApproved   { get; set; }
    public bool     IsAdmin      { get; set; }
    public DateTime CreatedAt    { get; set; }
    public DateTime LastLogin    { get; set; }
    public decimal  Coin         { get; set; }
}

public class MigrationReport
{
    public int           Migrated { get; set; }
    public int           Skipped  { get; set; }
    public int           Failed   { get; set; }
    public List<string>  Errors   { get; set; } = new();
}