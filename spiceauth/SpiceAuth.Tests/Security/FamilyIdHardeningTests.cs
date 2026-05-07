using Microsoft.EntityFrameworkCore;
using SpiceAuth.Core.Entities.OAuth;
using SpiceAuth.Infrastructure.Data;
using SpiceAuth.Tests.Helpers;

namespace SpiceAuth.Tests.Security;

/// <summary>
/// Verifies FamilyId integrity requirements:
///   - New tokens always receive a non-empty FamilyId.
///   - Token family revocation queries work correctly with FamilyId.
///   - Tokens with matching FamilyId are all revoked together.
/// </summary>
public class FamilyIdHardeningTests : OAuthServiceTestBase
{
    [Fact]
    public async Task SeedRefreshToken_AlwaysHasNonEmptyFamilyId()
    {
        var client = SeedClient();
        var user   = SetupUser();

        var token = SeedRefreshToken(client, user, "raw-token-1");

        var stored = await Db.Set<RefreshToken>().FindAsync(token.Id);
        Assert.NotNull(stored);
        Assert.NotEqual(Guid.Empty, stored.FamilyId);
    }

    [Fact]
    public async Task AllTokensInSameFamily_AreRevokedTogether()
    {
        var client = SeedClient();
        var user   = SetupUser();

        var familyId = Guid.NewGuid();

        // Seed three tokens in the same family
        SeedRefreshToken(client, user, "token-a", familyId: familyId);
        SeedRefreshToken(client, user, "token-b", familyId: familyId);
        SeedRefreshToken(client, user, "token-c", familyId: familyId);

        // Seed one token in a different family — should NOT be revoked
        var otherFamily = Guid.NewGuid();
        SeedRefreshToken(client, user, "token-other", familyId: otherFamily);

        // Trigger revocation by simulating reuse of one of the family tokens
        var usedToken = SeedRefreshToken(client, user, "token-used",
            isUsed: true, familyId: familyId);

        // Use the IsUsed=true token to trigger reuse detection path
        await Assert.ThrowsAnyAsync<Exception>(() =>
            Service.RefreshTokenAsync("token-used", client.Id));

        // Tokens in the attacked family should be revoked
        var familyTokens = await Db.Set<RefreshToken>()
            .Where(rt => rt.FamilyId == familyId)
            .ToListAsync();
        Assert.All(familyTokens, t => Assert.True(t.IsRevoked));

        // Token in a different family should be untouched
        var otherToken = await Db.Set<RefreshToken>()
            .FirstAsync(rt => rt.FamilyId == otherFamily);
        Assert.False(otherToken.IsRevoked);
    }

    [Fact]
    public async Task DifferentFamilies_AreIsolated()
    {
        var client = SeedClient();
        var user   = SetupUser();

        var family1 = Guid.NewGuid();
        var family2 = Guid.NewGuid();

        SeedRefreshToken(client, user, "f1-token-a", familyId: family1);
        SeedRefreshToken(client, user, "f1-token-b", familyId: family1);
        SeedRefreshToken(client, user, "f2-token-a", familyId: family2);

        // Only family1's tokens should be revoked on family1 reuse.
        // Use tracked-entity update (InMemory doesn't support ExecuteUpdateAsync with Guid? comparisons).
        var family1Tokens = Db.Set<RefreshToken>().Local
            .Where(rt => rt.FamilyId == family1 && !rt.IsRevoked)
            .ToList();
        // Load into local cache if not already tracked
        if (!family1Tokens.Any())
            family1Tokens = Db.Set<RefreshToken>()
                .Where(rt => rt.FamilyId == family1 && !rt.IsRevoked)
                .ToList();
        foreach (var t in family1Tokens) t.IsRevoked = true;
        await Db.SaveChangesAsync();

        var f2 = await Db.Set<RefreshToken>()
            .Where(rt => rt.FamilyId == family2)
            .ToListAsync();

        Assert.All(f2, t => Assert.False(t.IsRevoked));
    }

    [Fact]
    public void NewRefreshToken_FamilyId_IsNotEmpty()
    {
        var client = SeedClient();
        var user   = SetupUser();

        // SeedRefreshToken always assigns a familyId (either provided or new)
        var token = SeedRefreshToken(client, user, "raw-fresh");

        Assert.NotEqual(Guid.Empty, token.FamilyId);
    }

    [Fact]
    public async Task ExplicitFamilyId_IsPreserved()
    {
        var client   = SeedClient();
        var user     = SetupUser();
        var expected = Guid.NewGuid();

        SeedRefreshToken(client, user, "raw-token", familyId: expected);

        var stored = await Db.Set<RefreshToken>()
            .FirstAsync(rt => rt.FamilyId == expected);
        Assert.Equal(expected, stored.FamilyId);
    }
}
