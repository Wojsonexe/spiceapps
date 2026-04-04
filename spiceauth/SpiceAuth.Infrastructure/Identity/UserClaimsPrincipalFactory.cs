using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using SpiceAuth.Core.Entities.Identity;

namespace SpiceAuth.Infrastructure.Identity;

public class UserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser>
{
    public UserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        IOptions<IdentityOptions> optionsAccessor) 
        : base(userManager, optionsAccessor)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);
        identity.AddClaim(new Claim("firstName", user.FirstName ?? ""));
        identity.AddClaim(new Claim("lastName", user.LastName ?? ""));
        identity.AddClaim(new Claim("isActive", user.IsActive.ToString()));
        return identity;
    }
}