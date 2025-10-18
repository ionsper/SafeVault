using SafeVault.Services;

namespace SafeVault.Middleware;

public class AuditLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IAuditLogger _audit;

    public AuditLoggingMiddleware(RequestDelegate next, IAuditLogger audit)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        await _next(context);

        // Skip common static asset paths to avoid log noise.
        var path = context.Request.Path.Value ?? string.Empty;
        if (path.StartsWith("/lib/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/_framework/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/_content/", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("/favicon.ico", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var username = context.User?.Identity?.IsAuthenticated == true ? context.User.Identity?.Name : null;
        await _audit.LogAccessAsync(username, context.Request.Path + context.Request.QueryString, context.Response.StatusCode, context);
    }
}

public static class AuditLoggingExtensions
{
    public static IApplicationBuilder UseAuditLogging(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AuditLoggingMiddleware>();
    }
}
