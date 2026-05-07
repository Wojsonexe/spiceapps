using Serilog.Context;

namespace SpiceAuth.API.Middleware;

/// <summary>
/// Propagates X-Correlation-Id through the request/response pipeline.
/// If the header is absent, a new GUID is generated. The value is added
/// to the Serilog LogContext so every log line carries the correlation id.
/// </summary>
public sealed class CorrelationIdMiddleware(RequestDelegate next)
{
    private const string HeaderName = "X-Correlation-Id";

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = context.Request.Headers[HeaderName].FirstOrDefault()
            ?? Guid.NewGuid().ToString("N");

        context.Response.Headers[HeaderName] = correlationId;
        context.Items["CorrelationId"] = correlationId;

        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await next(context);
        }
    }
}
