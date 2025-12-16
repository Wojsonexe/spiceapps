using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;
using SpiceAuth.Domain.Enums;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class RegistrationRequestConfiguration : IEntityTypeConfiguration<RegistrationRequest>
{
    public void Configure(EntityTypeBuilder<RegistrationRequest> builder)
    {
        builder.ToTable("registration_requests");
        builder.HasKey(r => r.Id);
        
        builder.Property(r => r.Email).IsRequired().HasMaxLength(256);
        builder.Property(r => r.NormalizedEmail).IsRequired().HasMaxLength(256);
        builder.Property(r => r.Username).IsRequired().HasMaxLength(50);
        builder.Property(r => r.PasswordHash).IsRequired().HasMaxLength(512);
        builder.Property(r => r.SourceApp).IsRequired().HasMaxLength(50);
        builder.Property(r => r.Status).IsRequired().HasConversion<int>();
        builder.Property(r => r.RejectionReason).HasMaxLength(500);
        builder.Property(r => r.IpAddress).HasMaxLength(45);
        builder.Property(r => r.UserAgent).HasMaxLength(500);
        builder.Property(r => r.DiscordId).HasMaxLength(20);
        builder.Property(r => r.DiscordUsername).HasMaxLength(32);
        builder.Property(r => r.DiscordDiscriminator).HasMaxLength(4);
        builder.Property(r => r.DiscordAvatar).HasMaxLength(100);
        
        builder.HasIndex(r => r.Status).HasDatabaseName("ix_registration_requests_status");
        builder.HasIndex(r => r.NormalizedEmail).HasDatabaseName("ix_registration_requests_normalized_email");
        builder.HasIndex(r => r.DiscordId).HasDatabaseName("ix_registration_requests_discord_id");
        builder.HasIndex(r => r.SubmittedAt).HasDatabaseName("ix_registration_requests_submitted_at");
        
        builder.HasOne(r => r.ReviewedBy)
            .WithMany()
            .HasForeignKey(r => r.ReviewedByUserId)
            .OnDelete(DeleteBehavior.SetNull);
    }
}