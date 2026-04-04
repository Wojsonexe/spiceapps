namespace SpiceAuth.Application.DTOs.OAuth;

public record SetClientStatusRequest
{
    public bool IsActive { get; init; }
}