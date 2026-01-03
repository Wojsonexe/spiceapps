namespace SpiceAuth.Application.Services.Email;

public interface IEmailService
{
    Task SendEmailVerificationAsync(string email, string username, string verificationToken);
    Task SendPasswordResetAsync(string email, string username, string resetToken);
    Task SendRegistrationApprovedAsync(string email, string username);
    Task SendRegistrationRejectedAsync(string email, string username, string reason);
    Task SendWelcomeEmailAsync(string email, string username);
}