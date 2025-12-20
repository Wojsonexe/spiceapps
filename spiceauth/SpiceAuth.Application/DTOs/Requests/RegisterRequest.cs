using System.ComponentModel.DataAnnotations;

namespace SpiceAuth.Application.DTOs.Requests;

public class RegisterRequest
{
    [Required]
    [EmailAddress]
    [MaxLength(256)]
    public string Email { get; set; } = null!;

    [Required]
    [MinLength(3)]
    [MaxLength(50)]
    public string Username { get; set; } = null!;

    [Required]
    [MinLength(8)]
    [MaxLength(100)]
    public string Password { get; set; } = null!;

    [Required]
    [MaxLength(50)]
    public string SourceApp { get; set; } = "web";
}