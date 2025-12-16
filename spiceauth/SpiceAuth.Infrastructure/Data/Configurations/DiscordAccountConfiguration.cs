using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SpiceAuth.Domain.Entities;

namespace SpiceAuth.Infrastructure.Data.Configurations;

public class DiscordAccountConfiguration : IEntityTypeConfiguration<DiscordAccount>
{
    public void Configure(EntityTypeBuilder<DiscordAccount> builder)
    {
        builder.ToTable("discord_accounts");
        builder.HasKey(d => d.Id);
        
        builder.Property(d => d.DiscordId).IsRequired().HasMaxLength(20);
        builder.Property(d => d.Username).IsRequired().HasMaxLength(32);
        builder.Property(d => d.Discriminator).IsRequired().HasMaxLength(4);
        builder.Property(d => d.Avatar).HasMaxLength(100);
        builder.Property(d => d.Email).HasMaxLength(256);
        builder.Property(d => d.AccessToken).IsRequired().HasMaxLength(2048);
        builder.Property(d => d.RefreshToken).IsRequired().HasMaxLength(2048);
        
        builder.HasIndex(d => d.DiscordId).IsUnique().HasDatabaseName("ix_discord_accounts_discord_id");
        builder.HasIndex(d => d.UserId).IsUnique().HasDatabaseName("ix_discord_accounts_user_id");
        
        builder.HasOne(d => d.User)
            .WithOne(u => u.DiscordAccount)
            .HasForeignKey<DiscordAccount>(d => d.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}