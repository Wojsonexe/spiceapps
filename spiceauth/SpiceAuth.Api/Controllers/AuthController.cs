using Microsoft.AspNetCore.Mvc;
using SpiceAuth.Application.DTOs.Requests;
using SpiceAuth.Application.DTOs.Responses;
using SpiceAuth.Application.Interfaces;

namespace SpiceAuth.Api.Controllers;

[ApiController]
[Route("auth")]
public class AuthController : ControllerBase
{
    private readonly IUserService _userService;
    private readonly IRegistrationService _registrationService;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IUserService userService,
        IRegistrationService registrationService,
        IPasswordHasher passwordHasher,
        ILogger<AuthController> logger)
    {
        _userService = userService;
        _registrationService = registrationService;
        _passwordHasher = passwordHasher;
        _logger = logger;
    }

    /// <summary>
    /// Register a new user (creates pending registration request).
    /// Requires admin approval before user can login.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Check if user already exists
        var existingUser = await _userService.GetUserByEmailAsync(request.Email);
        if (existingUser != null)
        {
            return Conflict(new { error = "email_already_registered", message = "Email is already registered" });
        }

        // Check if there's a pending request
        var hasPendingRequest = await _registrationService.IsPendingRequestByEmailAsync(request.Email);
        if (hasPendingRequest)
        {
            return Conflict(new { error = "registration_pending", message = "Registration request is already pending approval" });
        }

        // Check username availability
        var existingUsername = await _userService.GetUserByUsernameAsync(request.Username);
        if (existingUsername != null)
        {
            return Conflict(new { error = "username_taken", message = "Username is already taken" });
        }

        // Hash password
        var passwordHash = _passwordHasher.HashPassword(request.Password);

        // Create registration request
        var registrationRequest = await _registrationService.CreateRegistrationRequestAsync(
            request.Email,
            request.Username,
            passwordHash,
            request.SourceApp,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            Request.Headers["User-Agent"].ToString()
        );

        _logger.LogInformation("Registration request submitted: {Email}", request.Email);

        return Ok(new RegistrationResponse
        {
            RequestId = registrationRequest.Id,
            Message = "Registration request submitted. Please wait for admin approval.",
            Status = "pending"
        });
    }

    /// <summary>
    /// Login with email and password.
    /// Returns user info if successful.
    /// Later: will redirect to /oauth/authorize for OAuth flow.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userService.ValidateCredentialsAsync(request.Email, request.Password);
        if (user == null)
        {
            return Unauthorized(new { error = "invalid_credentials", message = "Invalid email or password" });
        }

        // Update last login
        await _userService.UpdateLastLoginAsync(user.Id);

        _logger.LogInformation("User logged in: {Email}", user.Email);

        return Ok(new LoginResponse
        {
            UserId = user.Id,
            Username = user.Username,
            Email = user.Email,
            Message = "Login successful"
        });
    }
}