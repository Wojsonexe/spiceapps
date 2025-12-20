namespace SpiceAuth.Application.DTOs.Responses;

public class RegistrationResponse
{
    public Guid RequestId { get; set; }
    public string Message { get; set; } = null!;
    public string Status { get; set; } = "pending";
}