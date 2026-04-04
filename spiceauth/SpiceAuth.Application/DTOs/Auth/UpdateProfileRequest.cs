namespace SpiceAuth.Application.DTOs.Auth;

public class UpdateProfileRequest
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public int Department { get; set; }
    public DateOnly? BirthDay { get; set; }
    public string? ProfilePictureUrl { get; init; }
}