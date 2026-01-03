using Microsoft.EntityFrameworkCore;
using Serilog;
using SpiceAuth.Application.Services.Email;
using SpiceAuth.Application.Services.Identity;
using SpiceAuth.Application.Services.OAuth;
using SpiceAuth.Application.Services.Registration;
using SpiceAuth.Application.Services.Security;
using SpiceAuth.Application.Services.Token;
using SpiceAuth.Core.Entities.Security;
using SpiceAuth.Infrastructure.Data;
using SpiceAuth.Infrastructure.Identity;
using SpiceAuth.Infrastructure.Services;
using SpiceAuth.Infrastructure.Services.Email;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/spiceauth-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

Log.Information("Starting SpiceAuth API...");

try
{
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    builder.Services.AddDbContext<ApplicationDbContext>(options =>
    {
        if (builder.Environment.IsDevelopment())
        {
            // SQLite for development
            options.UseSqlite(connectionString);
        }
        else
        {
            // PostgreSQL for production
            options.UseNpgsql(connectionString);
        }

        // Enable detailed errors in development
        if (builder.Environment.IsDevelopment())
        {
            options.EnableSensitiveDataLogging();
            options.EnableDetailedErrors();
        }
    });
    
    builder.Services.AddScoped<IPasswordHasher, PasswordHasher>();
    builder.Services.AddScoped<IIdentityService, IdentityService>();
    builder.Services.AddScoped<IRegistrationService, RegistrationService>();
    builder.Services.AddScoped<IKeyManagementService, KeyManagementService>();
    builder.Services.AddScoped<ITokenService, TokenService>();
    builder.Services.AddScoped<IOAuthService, OAuthService>();
    builder.Services.AddScoped<IIdentityStore, EfIdentityStore>();
    builder.Services.AddScoped<IEmailService, EmailService>();
    
    // Register ApplicationDbContext as DbContext for services that use generic DbContext
    builder.Services.AddScoped<DbContext>(provider => 
        provider.GetRequiredService<ApplicationDbContext>());

    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(options =>
    {
        options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
        {
            Title = "SpiceAuth",
            Version = "v1",
            Description = "Enterprise Identity Provider & OAuth 2.1 Authorization Server"
        });
    });

    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
        {
            policy.AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader();
        });
    });

    builder.Services.AddRouting(options =>
    {
        options.LowercaseUrls = true;
    });

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        using var scope = app.Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        Log.Information("Running migrations...");
        await context.Database.MigrateAsync();

        Log.Information("Seeding database...");
        var passwordHasher = scope.ServiceProvider
            .GetRequiredService<IPasswordHasher>();
        await DbInitializer.SeedAsync(context, passwordHasher);
        
        var keyManagement = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();
        var activeKeys = await context.Set<SigningKey>().Where(k => k.IsActive).ToListAsync();
        if (!activeKeys.Any())
        {
            Log.Information("No signing keys found, generating initial key...");
            await keyManagement.CreateNewKeyAsync();
        }

        Log.Information("Database ready!");
    }

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseSerilogRequestLogging();

    app.UseHttpsRedirection();

    app.UseCors();

    app.UseAuthorization();

    app.MapControllers();
    app.MapControllerRoute(
        name: "oauth",
        pattern: "oauth/{action}",
        defaults: new { controller = "OAuth"  });

    Log.Information("SpiceAuth API started successfully on {Urls}", string.Join(", ", app.Urls));

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application start-up failed");
    throw;
}
finally
{
    Log.CloseAndFlush();
}