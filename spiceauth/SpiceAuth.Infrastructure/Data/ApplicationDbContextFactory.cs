using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SpiceAuth.Infrastructure.Data;

public class ApplicationDbContextFactory 
    : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();

        optionsBuilder.UseNpgsql(
            "Host=localhost;Port=5433;Database=spiceauth;Username=spicegears;Password=test"
        );

        return new ApplicationDbContext(optionsBuilder.Options);
    }
}