using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Diagnostics;

namespace SafeVault.Middleware;

/// <summary>
/// Middleware that records unhandled exceptions and HTTP error responses (status >= 400)
/// to a log file under the application's content root. This implementation favors
/// reliability and simplicity so entries are persisted even during shutdown.
/// </summary>
public class ExceptionLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _logPath;
    private static readonly string[] IgnoredStaticExtensions = new[]
    {
            ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"
        };

    public ExceptionLoggingMiddleware(RequestDelegate next, IWebHostEnvironment env)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        // Ensure a 'logs' directory exists under the content root and write to errors.txt
        var logsDir = Path.Combine(env.ContentRootPath, "logs");
        if (!Directory.Exists(logsDir)) Directory.CreateDirectory(logsDir);
        _logPath = Path.Combine(logsDir, "errors.txt");
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);

            // Log HTTP error responses (4xx and 5xx), but skip common static-asset 404s
            if (context.Response.StatusCode >= 400)
            {
                // Skip logging missing static assets (e.g. requests for /lib/* or images)
                // to avoid noisy logs that obscure real server-side errors.
                if (context.Response.StatusCode == 404 && IsLikelyStaticAsset(context.Request.Path))
                {
                    return;
                }

                // If the IExceptionHandlerFeature is present (set by UseExceptionHandler), prefer
                // logging the captured exception details rather than an empty error entry.
                var exFeature = context.Features.Get<IExceptionHandlerFeature>();
                if (exFeature?.Error != null)
                {
                    var messageEx = BuildLogEntry(context, exFeature.Error, context.Response.StatusCode);
                    await File.AppendAllTextAsync(_logPath, messageEx);
                    return;
                }

                var message = BuildLogEntry(context, null, context.Response.StatusCode);
                // Use async file append here to avoid blocking the request thread.
                await File.AppendAllTextAsync(_logPath, message);
            }
        }
        catch (Exception ex)
        {
            // If an exception escapes the pipeline, synchronously append the log entry to
            // reduce the chance of losing the record during abrupt shutdown.
            var message = BuildLogEntry(context, ex, statusCode: 500);
            File.AppendAllText(_logPath, message);

            // Re-throw the exception so upstream middleware or the host can perform additional handling.
            throw;
        }
    }

    private static string BuildLogEntry(HttpContext context, Exception? ex, int statusCode)
    {
        var ts = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
        var sb = new StringBuilder();
        sb.AppendLine("----");
        sb.AppendLine($"Timestamp (UTC): {ts}");
        sb.AppendLine($"Request: {context.Request.Method} {context.Request.Path}{context.Request.QueryString}");
        sb.AppendLine($"StatusCode: {statusCode}");
        if (ex != null)
        {
            sb.AppendLine($"Exception: {ex.GetType().FullName}: {ex.Message}");
            sb.AppendLine("StackTrace:");
            sb.AppendLine(ex.StackTrace ?? "(no stack)");
        }
        sb.AppendLine();
        return sb.ToString();
    }

    private static bool IsLikelyStaticAsset(PathString path)
    {
        var p = path.Value ?? string.Empty;
        // Common folders used for static assets / framework content
        if (p.StartsWith("/lib/", StringComparison.OrdinalIgnoreCase)
            || p.StartsWith("/_framework/", StringComparison.OrdinalIgnoreCase)
            || p.StartsWith("/_content/", StringComparison.OrdinalIgnoreCase)
            || p.StartsWith("/favicon.ico", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var ext = Path.GetExtension(p);
        if (!string.IsNullOrEmpty(ext))
        {
            return IgnoredStaticExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
        }

        return false;
    }
}

// Extension method to register middleware fluently
public static class ExceptionLoggingMiddlewareExtensions
{
    public static IApplicationBuilder UseExceptionFileLogging(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ExceptionLoggingMiddleware>();
    }
}
