namespace SpiceAuth.Application.Common;

public class OperationResult
{
    public bool Success { get; set; } = false;
    public string? Message { get; set; } = null;
}