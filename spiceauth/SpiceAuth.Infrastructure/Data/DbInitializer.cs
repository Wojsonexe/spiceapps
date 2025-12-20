using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Interfaces;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data;

public static class DbInitializer
{
    public static async Task InitializeAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<SpiceAuthDbContext>();
        var passwordHasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher>();
        var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>()
            .CreateLogger("DbInitializer");

        var strategy = context.Database.CreateExecutionStrategy();

        await strategy.ExecuteAsync(async () =>
        {
            await using var transaction = await context.Database.BeginTransactionAsync();

            try
            {
                await SeedRolesAsync(context, logger);
                await SeedSuperAdminAsync(context, passwordHasher, logger);

                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                logger.LogCritical(ex, "Database initialization failed");
                throw;
            }
        });
    }

    private static async Task SeedRolesAsync(
        SpiceAuthDbContext context,
        ILogger logger)
    {
        if (await context.Roles.AnyAsync())
            return;

        context.Roles.AddRange(
            new Role { Id = Guid.NewGuid(), Name = "Admin" },
            new Role { Id = Guid.NewGuid(), Name = "User" }
        );

        await context.SaveChangesAsync();
        logger.LogInformation("Roles seeded");
    }

    private static async Task SeedSuperAdminAsync(
        SpiceAuthDbContext context,
        IPasswordHasher passwordHasher,
        ILogger logger)
    {
        const string adminEmail = "admin@spiceauth.local";

        if (await context.Users.AnyAsync(u => u.Email == adminEmail))
        {
            logger.LogInformation("SuperAdmin already exists");
            return;
        }

        var admin = new User
        {
            Id = Guid.NewGuid(),
            Email = adminEmail,
            NormalizedEmail = adminEmail.ToUpperInvariant(),
            Username = "admin",
            PasswordHash = passwordHasher.HashPassword("AdminPass123!"),
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        context.Users.Add(admin);

        var adminRole = await context.Roles.FirstAsync(r => r.Name == "Admin");

        context.UserRoles.Add(new UserRole
        {
            UserId = admin.Id,
            RoleId = adminRole.Id,
            GrantedAt = DateTime.UtcNow
        });

        await context.SaveChangesAsync();

        logger.LogWarning(
            "SuperAdmin created | email={Email} | password=AdminPass123!",
            adminEmail);
    }
}
