using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Security;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class MfaSettingsConfiguration : IEntityTypeConfiguration<MfaSettings>
{
    public void Configure(EntityTypeBuilder<MfaSettings> builder)
    {
        builder.HasKey(m => m.UserId);
        
        builder.Property(m => m.TotpSecret)
            .HasMaxLength(255);
        
        builder.Property(m => m.BackupCodes)
            .HasColumnType("jsonb"); // PostgreSQL

        // Indexes
        builder.HasIndex(m => m.IsEnabled)
            .HasDatabaseName("IX_MfaSettings_IsEnabled");
    }
}