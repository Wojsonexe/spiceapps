using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Core.Entities.Registration;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class RegistrationRequestConfiguration : IEntityTypeConfiguration<RegistrationRequest>
{
    public void Configure(EntityTypeBuilder<RegistrationRequest> builder)
    {
        builder.HasKey(r => r.Id);
        
        builder.Property(r => r.Email)
            .IsRequired()
            .HasMaxLength(255);
        
        builder.Property(r => r.Username)
            .IsRequired()
            .HasMaxLength(50);
        
        builder.Property(r => r.FirstName)
            .HasMaxLength(100);
        
        builder.Property(r => r.LastName)
            .HasMaxLength(100);
        
        builder.Property(r => r.RejectionReason)
            .HasMaxLength(500);
        
        builder.Property(r => r.ExternalProvider)
            .HasMaxLength(50);
        
        builder.Property(r => r.ExternalProviderId)
            .HasMaxLength(255);

        // Indexes
        builder.HasIndex(r => r.Email)
            .HasDatabaseName("IX_RegistrationRequests_Email");
        
        builder.HasIndex(r => r.Status)
            .HasDatabaseName("IX_RegistrationRequests_Status");
        
        builder.HasIndex(r => r.RequestedAt)
            .HasDatabaseName("IX_RegistrationRequests_RequestedAt");
    }
}