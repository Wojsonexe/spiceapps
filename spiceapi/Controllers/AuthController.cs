using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Serilog;
using SpiceAPI.Auth;
using SpiceAPI.Helpers;
using SpiceAPI.Models;
using System.Net.Http.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace SpiceAPI.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly DataContext db;
        private readonly Crypto crypto;
        private readonly Token tg;
        private readonly IHttpClientFactory _http;
        private readonly IConfiguration _config;

        private bool AuthLimitEnabled = false;
        private string AuthSecHeader = "";

        public AuthController(DataContext dataContext, Crypto crt, Token token,
            IHttpClientFactory http, IConfiguration config)
        {
            db = dataContext;
            crypto = crt;
            tg = token;
            _http = http;
            _config = config;
            var authsec = Environment.GetEnvironmentVariable("AUTHSEC");
            if (string.IsNullOrWhiteSpace(authsec) || authsec == "none")
            {
                AuthLimitEnabled = false;
            }
            else
            {
                AuthLimitEnabled = true;
                AuthSecHeader = authsec;
            }
        }

        public class LoginHeaders() //header names used for controller
        {
            public string Login { get; set; }
            public string Password { get; set; }
        }

        public class RegisterHeaders()
        {
            public string Email { get; set; }
            public string Password { get; set; }
            public string Name { get; set; }
            public string Surname { get; set; }
            public DateOnly Birthday { get; set; }

            public string Department { get; set; }
        }

        public class TokenResponse //returning tokens as response body
        {
            public string Access_Token { get; set; }
            public string Refresh_Token { get; set; }
        }

        private record SpiceAuthResponse(
            string? access_token,
            string? refresh_token,
            int     expires_in);

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginHeaders form)
        {
            if (AuthLimitEnabled)
            {
                var ip = Request.Headers[AuthSecHeader].FirstOrDefault();
                if (ip == null) return BadRequest(new ErrorResponse($"An {AuthSecHeader} containing ip is required", "AUTHSEC_INVALID_REQ", "You must provide correct headers, check proxy"));

                LoginErrorAttempt? loginError = await db.LoginErrorAttempts.FirstOrDefaultAsync(i => i.Ip == ip);
                if (loginError != null)
                {
                    if (loginError.RetryCount >= 5)
                    {
                        var now = DateTime.UtcNow;
                        if (loginError.LastRetry.AddMinutes(15) <= now)
                        {
                            db.LoginErrorAttempts.Remove(loginError);
                            await db.SaveChangesAsync();
                        }
                        else return Unauthorized();
                    }
                }
            }

            User? user = await db.Users.Where(u => u.Email == form.Login).FirstOrDefaultAsync();
            if (user == null)
            {
                return NotFound();
            }

            bool passwordTest = crypto.TestPassword(form.Password, user.Password);

            if (passwordTest)
            {
                if (AuthLimitEnabled) //clear login attempts to zero
                {
                    var ip = Request.Headers[AuthSecHeader].FirstOrDefault();
                    if (ip == null) return BadRequest(new ErrorResponse($"An {AuthSecHeader} containing ip is required", "AUTHSEC_INVALID_REQ", "You must provide correct headers, check proxy"));

                    LoginErrorAttempt? loginError = await db.LoginErrorAttempts.FirstOrDefaultAsync(i => i.Ip == ip);
                    if (loginError != null)
                    {
                        db.LoginErrorAttempts.Remove(loginError);
                        await db.SaveChangesAsync();
                    }
                }

                // ── delegate token issuance to SpiceAuth ──────────────────────
                var secret = _config["SpiceAuth:InternalSecret"]
                    ?? throw new InvalidOperationException("SpiceAuth:InternalSecret not configured");

                var httpClient = _http.CreateClient("spiceauth");
                var payload = new
                {
                    userId    = user.Id,
                    clientId  = "spiceapi-internal",
                    scope     = "openid profile",
                    email     = user.Email,
                    firstName = user.FirstName,
                    lastName  = user.LastName,
                    isApproved = user.IsApproved
                };

                SpiceAuthResponse? tokens = null;
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    try
                    {
                        var req = new HttpRequestMessage(HttpMethod.Post, "/api/internal/issue-token")
                        {
                            Content = JsonContent.Create(payload)
                        };
                        req.Headers.Add("X-Internal-Secret", secret);

                        var resp = await httpClient.SendAsync(req);
                        resp.EnsureSuccessStatusCode();
                        tokens = await resp.Content.ReadFromJsonAsync<SpiceAuthResponse>();
                        break;
                    }
                    catch (HttpRequestException) when (attempt < 3)
                    {
                        await Task.Delay(200);
                    }
                }

                if (tokens?.access_token is null || tokens.refresh_token is null)
                    return StatusCode(502, new ErrorResponse("Authentication service unavailable", "AUTH_SERVICE_DOWN"));

                return Ok(new TokenResponse
                {
                    Access_Token  = tokens.access_token,
                    Refresh_Token = tokens.refresh_token
                });
            }

            else
            {
                if (AuthLimitEnabled)
                {
                    var ip = Request.Headers[AuthSecHeader].FirstOrDefault();
                    if (ip == null) return BadRequest(new ErrorResponse($"An {AuthSecHeader} containing ip is required", "AUTHSEC_INVALID_REQ", "You must provide correct headers, check proxy"));

                    LoginErrorAttempt? loginError = await db.LoginErrorAttempts.FirstOrDefaultAsync(i => i.Ip == ip);
                    if (loginError != null)
                    {
                        loginError.LastRetry = DateTime.UtcNow;
                        loginError.RetryCount++;
                        await db.SaveChangesAsync();
                    }
                    else
                    {
                        LoginErrorAttempt firstAtt = new LoginErrorAttempt()
                        {
                            Ip = ip,
                            LastRetry = DateTime.UtcNow,
                            RetryCount = 1,
                        };
                        await db.LoginErrorAttempts.AddAsync(firstAtt);
                        await db.SaveChangesAsync();
                    }
                }
                //wrong password
                return Unauthorized();
            }
        }

        [NonAction]
        public static bool IsStrongPassword(string password, out List<ErrorResponse> errors)
        {
            errors = new();

            if (string.IsNullOrWhiteSpace(password))
            {
                errors.Add(new("Hasło nie może być puste.", "PASSWORD_EMPTY"));
                return false;
            }

            if (password.Length < 7)
                errors.Add(new("Hasło musi mieć co najmniej 7 znaków.", "PASSWORD_TOO_SHORT"));

            if (!password.Any(char.IsUpper))
                errors.Add(new("Hasło musi zawierać co najmniej jedną wielką literę.", "PASSWORD_NO_UPPER"));

            if (!password.Any(char.IsLower))
                errors.Add(new("Hasło musi zawierać co najmniej jedną małą literę.", "PASSWORD_NO_LOWER"));

            if (!password.Any(char.IsDigit) && !password.Any(char.IsSymbol))
                errors.Add(new("Hasło musi zawierać co najmniej jedną cyfrę lub znak specjalny.", "PASSWORD_NO_SPECIAL"));

            return errors.Count == 0;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterHeaders ui)
        {
            switch (ui.Department)
            {
                case "programmer":
                    break;
                case "mechanic":
                    break;
                case "socialmedia":
                    break;
                case "marketing":
                    break;
                case "mentor":
                    break;
                case "executive":
                    break;
                default: return BadRequest($"Department parameter: {ui.Department} is not an allowed value");
            }
            List<ErrorResponse> innerErrors = new();
            if (!IsStrongPassword(ui.Password, out innerErrors))
            {
                var err = new ErrorResponse("Password is too weak", "PASSWORD_TOO_WEAK", "One or more criteria were not met", innerErrors);
                return BadRequest(err);
            }


            User user = new User();
            user.CreatedAt = DateTime.UtcNow;
            user.FirstName = ui.Name;
            user.LastName = ui.Surname;
            user.Email = ui.Email;
            user.Id = Guid.NewGuid();
            user.Password = crypto.Hash(ui.Password);
            user.IsApproved = false;
            user.BirthDay = ui.Birthday;
            switch (ui.Department)
            {
                case "programmer":
                    user.Department = Department.Programmers;
                    break;
                case "mechanic":
                    user.Department = Department.Mechanics;
                    break;
                case "socialmedia":
                    user.Department = Department.SocialMedia;
                    break;
                case "marketing":
                    user.Department = Department.Marketing;
                    break;
                case "mentor":
                    user.Department = Department.Mentor;
                    break;
                case "executive":
                    user.Department = Department.Executive;
                    break;
                default: return BadRequest(new ErrorResponse("Department value is invalid", "INVALID_FORM", "Department parameter may only be: programmer, mechanic, socialmedia, marketing, mentor, executive"));
            }

            await db.Users.AddAsync(user);
            await db.SaveChangesAsync();

            return Ok(new UserInfo(user));
        }

        [HttpGet("logoutAll")]
        public async Task<IActionResult> InvalidateRefreshTokens([FromHeader] string? Authorization)
        {
            if (Authorization == null) { return Unauthorized("Provide an Access Token to continue"); }
            bool isValid = tg.VerifyToken(Authorization);
            if (!isValid) { return StatusCode(403, "Invalid Token"); }

            User? user = await tg.RetrieveUser(Authorization);
            if (user == null) { return BadRequest("NULL USER"); }

            var secret = _config["SpiceAuth:InternalSecret"]
                ?? throw new InvalidOperationException("SpiceAuth:InternalSecret not configured");

            var httpClient = _http.CreateClient("spiceauth");
            var req = new HttpRequestMessage(HttpMethod.Post, "/api/internal/revoke-all-tokens")
            {
                Content = JsonContent.Create(new { userId = user.Id })
            };
            req.Headers.Add("X-Internal-Secret", secret);

            HttpResponseMessage resp;
            try { resp = await httpClient.SendAsync(req); }
            catch (HttpRequestException) { return StatusCode(502, new ErrorResponse("Authentication service unavailable", "AUTH_SERVICE_DOWN")); }

            if (!resp.IsSuccessStatusCode)
                return StatusCode(502, new ErrorResponse("Authentication service error", "AUTH_SERVICE_ERROR"));

            return Ok();
        }

        [HttpGet("logout")]
        public async Task<IActionResult> Logout([FromHeader] string? Authorization)
        {
            if (Authorization == null) { return BadRequest("Provide the refresh token to continue"); }

            var secret = _config["SpiceAuth:InternalSecret"]
                ?? throw new InvalidOperationException("SpiceAuth:InternalSecret not configured");

            var httpClient = _http.CreateClient("spiceauth");
            var req = new HttpRequestMessage(HttpMethod.Post, "/api/internal/revoke-token")
            {
                Content = JsonContent.Create(new { refreshToken = Authorization })
            };
            req.Headers.Add("X-Internal-Secret", secret);

            HttpResponseMessage resp;
            try { resp = await httpClient.SendAsync(req); }
            catch (HttpRequestException) { return StatusCode(502, new ErrorResponse("Authentication service unavailable", "AUTH_SERVICE_DOWN")); }

            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return BadRequest("This token does not exist");

            if (!resp.IsSuccessStatusCode)
                return StatusCode(502, new ErrorResponse("Authentication service error", "AUTH_SERVICE_ERROR"));

            return Ok();
        }

        [HttpGet("getUser")]
        public async Task<IActionResult> getUser([FromHeader] string? Authorization)
        {
            if (Authorization == null) { return Unauthorized("Provide an Access Token to continue"); }
            bool isValid = tg.VerifyToken(Authorization);
            if (!isValid) { return StatusCode(403, "Invalid Token"); }

            User? user = await tg.RetrieveUser(Authorization);
            if (user == null) { return BadRequest("NULL USER"); }

            return Ok(new UserInfo(user));
        }

        [HttpPost("generateAccess")]
        public async Task<IActionResult> GenerateAccess([FromHeader] string? Authorization)
        {
            if (Authorization == null) { return Unauthorized("Provide refresh token to continue"); }

            var secret = _config["SpiceAuth:InternalSecret"]
                ?? throw new InvalidOperationException("SpiceAuth:InternalSecret not configured");

            var httpClient = _http.CreateClient("spiceauth");
            var req = new HttpRequestMessage(HttpMethod.Post, "/api/internal/refresh-token")
            {
                Content = JsonContent.Create(new { refreshToken = Authorization })
            };
            req.Headers.Add("X-Internal-Secret", secret);

            HttpResponseMessage resp;
            try { resp = await httpClient.SendAsync(req); }
            catch (HttpRequestException) { return StatusCode(502, new ErrorResponse("Authentication service unavailable", "AUTH_SERVICE_DOWN")); }

            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return NotFound("No such refresh token exists");

            if (!resp.IsSuccessStatusCode)
                return StatusCode(502, new ErrorResponse("Authentication service error", "AUTH_SERVICE_ERROR"));

            var accessToken = await resp.Content.ReadAsStringAsync();
            return Content(accessToken, "text/plain");
        }

        public class ChangePasswordBody { public string OldPassword { get; set; } public string NewPassword { get; set; } }

        [HttpPut("changePassword")]
        public async Task<IActionResult> ChangePassword([FromHeader] string? Authorization, [FromBody] ChangePasswordBody body)
        {
            if (Authorization == null) { return Unauthorized("Provide an Access Token to continue"); }
            bool isValid = tg.VerifyToken(Authorization);
            if (!isValid) { return StatusCode(403, "Invalid Token"); }

            string[] token = Authorization.Split('.');

            Log.Logger.Information(Encoding.UTF8.GetString(
                    Convert.FromBase64String(token[0])
                    ));

            UserToken? ut = System.Text.Json.JsonSerializer.Deserialize<UserToken>(
                Encoding.UTF8.GetString(
                    Convert.FromBase64String(token[0])
                    )
                );
            if (ut == null) return NotFound();
            User? user = await db.Users.FindAsync(ut.Sub);
            if (user == null) { return BadRequest("NULL USER"); }

            if (crypto.TestPassword(body.OldPassword, user.Password))
            {
                if (!IsStrongPassword(body.NewPassword, out var errors))
                {
                    var err = new ErrorResponse("Password is too weak", "PASSWORD_TOO_WEAK", "One or more criteria were not met", errors);
                    return BadRequest(err);
                }
                user.Password = crypto.Hash(body.NewPassword);
                await db.SaveChangesAsync();
                return Ok(new UserInfo(user));
            }
            else
            {
                return StatusCode(409, "Password Mismatch");
            }
        }

        public class RecoveryResetPasswordBody
        {
            public string Email { get; set; }
            public string ResetCode { get; set; }
            public string NewPassword { get; set; }
        }

        [HttpPut("recoveryResetPassword")]
        public async Task<IActionResult> RecoveryResetPassword(
            [FromHeader] string? Authorization,
            [FromBody] RecoveryResetPasswordBody body
            )
        {
            User? user = await db.Users.FirstOrDefaultAsync(u => u.Email == body.Email);

            if (user == null)
            {
                return NotFound("This account does not exist!");
            }

            UserRecoveryCode? key = await db.RecoveryCodes.FirstOrDefaultAsync(r => r.Code == body.ResetCode);

            if (key == null) return BadRequest("Bad request.");

            if (key.UserId != user.Id) return BadRequest("Bad request.");

            if (!IsStrongPassword(body.NewPassword, out var errors))
            {
                var err = new ErrorResponse("Password is too weak", "PASSWORD_TOO_WEAK", "One or more criteria were not met", errors);
                return BadRequest(err);
            }
            user.Password = crypto.Hash(body.NewPassword);
            db.RecoveryCodes.Remove(key); //remove the used recovery code
            await db.SaveChangesAsync();
            return Ok(new UserInfo(user));
        }
    }
}
