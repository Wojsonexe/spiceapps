using System.ComponentModel.DataAnnotations;

namespace SpiceAuth.Application.DTOs.Requests;

public class LoginRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = null!;

    [Required]
    public string Password { get; set; } = null!;
}