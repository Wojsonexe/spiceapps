namespace SpiceAuth.Application.DTOs.Responses;

public class LoginResponse
{
    public Guid UserId { get; set; }
    public string Username { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Message { get; set; } = "Login successful";
}