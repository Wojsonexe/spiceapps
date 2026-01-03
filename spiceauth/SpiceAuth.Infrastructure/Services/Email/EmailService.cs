// EmailService.cs
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SpiceAuth.Application.Services.Email;

namespace SpiceAuth.Infrastructure.Services.Email;

public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;
    private readonly IConfiguration _configuration;
    private readonly string _baseUrl;
    private readonly string _fromEmail;
    private readonly string _fromName;

    public EmailService(
        ILogger<EmailService> logger,
        IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
        
        _baseUrl = configuration["App:BaseUrl"] ?? "http://localhost:5000";
        _fromEmail = configuration["Email:FromEmail"] ?? "noreply@spiceauth.local";
        _fromName = configuration["Email:FromName"] ?? "SpiceAuth";
    }

    public async Task SendEmailVerificationAsync(string email, string username, string verificationToken)
    {
        var verificationUrl = $"{_baseUrl}/verify-email?token={verificationToken}";
        
        var subject = "Verify your email address";
        var body = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Welcome to SpiceAuth! 🎉</h1>
        </div>
        <div class='content'>
            <p>Hi <strong>{username}</strong>,</p>
            
            <p>Thank you for registering with SpiceAuth. Please verify your email address to activate your account.</p>
            
            <div style='text-align: center;'>
                <a href='{verificationUrl}' class='button'>Verify Email Address</a>
            </div>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style='word-break: break-all; color: #667eea;'>{verificationUrl}</p>
            
            <p>This link will expire in 24 hours for security reasons.</p>
            
            <p>If you didn't create an account with SpiceAuth, please ignore this email.</p>
        </div>
        <div class='footer'>
            <p>© 2025 SpiceAuth. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

        await SendEmailAsync(email, subject, body);
        
        _logger.LogInformation("Email verification sent to {Email}", email);
    }

    public async Task SendPasswordResetAsync(string email, string username, string resetToken)
    {
        var resetUrl = $"{_baseUrl}/reset-password?token={resetToken}";
        
        var subject = "Reset your password";
        var body = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; padding: 12px 30px; background: #f5576c; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .warning {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Password Reset Request 🔐</h1>
        </div>
        <div class='content'>
            <p>Hi <strong>{username}</strong>,</p>
            
            <p>We received a request to reset your password for your SpiceAuth account.</p>
            
            <div style='text-align: center;'>
                <a href='{resetUrl}' class='button'>Reset Password</a>
            </div>
            
            <p>Or copy and paste this link into your browser:</p>
            <p style='word-break: break-all; color: #f5576c;'>{resetUrl}</p>
            
            <div class='warning'>
                <strong>⚠️ Security Notice:</strong><br>
                This link will expire in 1 hour. If you didn't request a password reset, please ignore this email and ensure your account is secure.
            </div>
        </div>
        <div class='footer'>
            <p>© 2025 SpiceAuth. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

        await SendEmailAsync(email, subject, body);
        
        _logger.LogInformation("Password reset email sent to {Email}", email);
    }

    public async Task SendRegistrationApprovedAsync(string email, string username)
    {
        var loginUrl = $"{_baseUrl}/login";
        
        var subject = "Your registration has been approved! 🎉";
        var body = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .button {{ display: inline-block; padding: 12px 30px; background: #43e97b; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Welcome to SpiceAuth! ✨</h1>
        </div>
        <div class='content'>
            <p>Hi <strong>{username}</strong>,</p>
            
            <p>Great news! Your registration has been approved and your account is now active.</p>
            
            <p>You can now log in and start using SpiceAuth services.</p>
            
            <div style='text-align: center;'>
                <a href='{loginUrl}' class='button'>Log In Now</a>
            </div>
        </div>
        <div class='footer'>
            <p>© 2025 SpiceAuth. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

        await SendEmailAsync(email, subject, body);
        
        _logger.LogInformation("Registration approved email sent to {Email}", email);
    }

    public async Task SendRegistrationRejectedAsync(string email, string username, string reason)
    {
        var subject = "Registration Update";
        var body = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: #6c757d; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .reason {{ background: #fff; border-left: 4px solid #dc3545; padding: 15px; margin: 20px 0; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Registration Update</h1>
        </div>
        <div class='content'>
            <p>Hi <strong>{username}</strong>,</p>
            
            <p>Thank you for your interest in SpiceAuth. Unfortunately, we're unable to approve your registration at this time.</p>
            
            <div class='reason'>
                <strong>Reason:</strong><br>
                {reason}
            </div>
            
            <p>If you have any questions, please contact our support team.</p>
        </div>
        <div class='footer'>
            <p>© 2025 SpiceAuth. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

        await SendEmailAsync(email, subject, body);
        
        _logger.LogInformation("Registration rejected email sent to {Email}", email);
    }

    public async Task SendWelcomeEmailAsync(string email, string username)
    {
        var subject = "Welcome to SpiceAuth!";
        var body = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
        .content {{ background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h1>Welcome to SpiceAuth! 🚀</h1>
        </div>
        <div class='content'>
            <p>Hi <strong>{username}</strong>,</p>
            
            <p>Your account has been successfully created and verified!</p>
            
            <p>You can now enjoy all the features of SpiceAuth:</p>
            <ul>
                <li>Secure authentication</li>
                <li>OAuth 2.1 integration</li>
                <li>Multi-factor authentication</li>
                <li>Organization management</li>
            </ul>
            
            <p>If you need help getting started, check out our documentation or contact support.</p>
        </div>
        <div class='footer'>
            <p>© 2025 SpiceAuth. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

        await SendEmailAsync(email, subject, body);
        
        _logger.LogInformation("Welcome email sent to {Email}", email);
    }

    private async Task SendEmailAsync(string to, string subject, string htmlBody)
    {
        // TODO: Implement actual email sending (SMTP, SendGrid, AWS SES, etc.)
        // For now, just log it
        
        _logger.LogInformation(
            "EMAIL SENT:\nFrom: {FromName} <{FromEmail}>\nTo: {To}\nSubject: {Subject}",
            _fromName, _fromEmail, to, subject);
        
        // In production, you would use a real email service:
        // await _smtpClient.SendMailAsync(new MailMessage(...));
        // or
        // await _sendGridClient.SendEmailAsync(...);
        
        await Task.CompletedTask;
    }
}