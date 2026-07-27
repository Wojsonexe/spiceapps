using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Serilog;
using SpiceAPI.Models;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace SpiceAPI.Auth
{
    public class Token
    {
        private readonly SignatureCrypto sc;
        private readonly DataContext db;
        private readonly IHttpClientFactory _http;
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _config;

        private const string JwksCacheKey = "spiceauth_jwks";
        private static readonly TimeSpan JwksTtl = TimeSpan.FromMinutes(60);

        public Token(SignatureCrypto _sc, DataContext db,
            IHttpClientFactory http, IMemoryCache cache, IConfiguration config)
        {
            sc = _sc;
            this.db = db;
            _http = http;
            _cache = cache;
            _config = config;
        }

        // ── Format detection ──────────────────────────────────────────────────

        private static bool IsJwt(string token) =>
            token.StartsWith("ey", StringComparison.Ordinal) &&
            token.Count(c => c == '.') == 2;

        // ── JWKS fetch + cache ────────────────────────────────────────────────

        private async Task<IList<SecurityKey>> GetJwksKeysAsync()
        {
            if (_cache.TryGetValue(JwksCacheKey, out IList<SecurityKey>? cached) && cached is not null)
                return cached;

            var client = _http.CreateClient("spiceauth");
            var json   = await client.GetStringAsync("/.well-known/jwks.json");
            var keys   = new JsonWebKeySet(json).GetSigningKeys();

            _cache.Set(JwksCacheKey, keys, JwksTtl);
            return keys;
        }

        // ── JWT path ──────────────────────────────────────────────────────────

        private bool VerifyJwt(string token)
        {
            try
            {
                var keys     = GetJwksKeysAsync().GetAwaiter().GetResult();
                var issuer   = _config["SpiceAuth:Issuer"];
                var audience = _config["SpiceAuth:Audience"];

                new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys        = keys,
                    ValidateIssuer           = !string.IsNullOrWhiteSpace(issuer),
                    ValidIssuer              = issuer,
                    ValidateAudience         = !string.IsNullOrWhiteSpace(audience),
                    ValidAudience            = audience,
                    ValidateLifetime         = true,
                    ClockSkew                = TimeSpan.FromMinutes(5)
                }, out _);

                return true;
            }
            catch (Exception ex)
            {
                Log.Logger.Warning(ex, "JWT validation failed");
                return false;
            }
        }

        private async Task<User?> RetrieveUserFromJwt(string token)
        {
            try
            {
                var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
                var sub = jwt.Claims.FirstOrDefault(c =>
                    c.Type == JwtRegisteredClaimNames.Sub || c.Type == "sub")?.Value;

                if (string.IsNullOrWhiteSpace(sub) || !Guid.TryParse(sub, out var userId))
                    return null;

                var user = await db.Users.Include(u => u.Roles)
                    .FirstOrDefaultAsync(u => u.Id == userId);

                if (user != null) return user;

                // Auto-provision user from JWT claims (first login via external OAuth)
                var email      = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value ?? "";
                var isApproved = jwt.Claims.FirstOrDefault(c => c.Type == "is_approved")?.Value == "true";
                var deptRaw    = jwt.Claims.FirstOrDefault(c => c.Type == "department")?.Value;
                var dept       = int.TryParse(deptRaw, out var d) ? (Department)d : Department.NaDr;

                var provisioned = new User
                {
                    Id         = userId,
                    Email      = email,
                    IsApproved = isApproved,
                    Department = dept,
                    CreatedAt  = DateTime.UtcNow,
                    LastLogin  = DateTime.UtcNow,
                };

                db.Users.Add(provisioned);
                await db.SaveChangesAsync();
                Log.Logger.Information("Auto-provisioned SpiceAPI user {UserId} from JWT (external OAuth)", userId);
                return provisioned;
            }
            catch (Exception ex)
            {
                Log.Logger.Warning(ex, "Failed to extract user from JWT");
                return null;
            }
        }

        // ── Legacy RSA path ───────────────────────────────────────────────────

        private bool VerifyLegacy(string b64token)
        {
            string[] parts;
            try
            {
                parts = b64token.Split('.');
                if (parts.Length < 2)
                    throw new IndexOutOfRangeException("Token does not contain both payload and signature.");
            }
            catch (IndexOutOfRangeException e)
            {
                Log.Logger.Error(e, "Token format is invalid: {Token}", b64token);
                return false;
            }

            string tokenstr = Encoding.UTF8.GetString(Convert.FromBase64String(parts[0]));

            if (sc.VerifyData(tokenstr, parts[1]))
            {
                UserToken tok = JsonConvert.DeserializeObject<UserToken>(tokenstr)!;
                return tok.Expires > DateTime.UtcNow;
            }

            return false;
        }

        private async Task<User?> RetrieveUserLegacy(string b64token)
        {
            string[] parts = b64token.Split('.');

            Log.Logger.Information(Encoding.UTF8.GetString(Convert.FromBase64String(parts[0])));

            UserToken? ut = System.Text.Json.JsonSerializer.Deserialize<UserToken>(
                Encoding.UTF8.GetString(Convert.FromBase64String(parts[0])));

            if (ut == null) return null;
            return await db.Users.Include(u => u.Roles)
                .FirstOrDefaultAsync(u => u.Id == ut.Sub);
        }

        // ── Public API ────────────────────────────────────────────────────────

        public string GenerateToken(UserToken token)
        {
            string tokenstr    = System.Text.Json.JsonSerializer.Serialize(token,
                new System.Text.Json.JsonSerializerOptions { AllowTrailingCommas = false, WriteIndented = false });
            string tokenBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(tokenstr), Base64FormattingOptions.None);
            string signature   = Convert.ToBase64String(sc.SignData(tokenstr), Base64FormattingOptions.None);
            return $"{tokenBase64}.{signature}";
        }

        public bool VerifyToken(string b64token) =>
            IsJwt(b64token) ? VerifyJwt(b64token) : VerifyLegacy(b64token);

        public async Task<User?> RetrieveUser(string b64token) =>
            IsJwt(b64token)
                ? await RetrieveUserFromJwt(b64token)
                : await RetrieveUserLegacy(b64token);
    }

    public class RefreshToken
    {
        [Key]
        public string Token { get; set; }
        public Guid UserID { get; set; }
    }
}
