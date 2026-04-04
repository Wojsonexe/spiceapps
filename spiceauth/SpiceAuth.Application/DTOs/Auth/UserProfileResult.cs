namespace SpiceAuth.Application.DTOs.Auth;

public class UserProfileResult
{
    public bool Success { get; set; } = false;
    public string? Message { get; set; }
    public UserProfileDto? Data { get; set; }
}

public class UserProfileDto
{
    public Guid Id { get; set; }
    public string Email { get; set; } = "";
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public int Department { get; set; }
    public bool IsApproved { get; set; }
    public DateOnly? BirthDay { get; set; }
}