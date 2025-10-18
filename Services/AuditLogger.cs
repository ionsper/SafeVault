using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace SafeVault.Services;

/// <summary>
/// Lightweight audit logger for authentication and access events. Implementations
/// append structured, timestamped lines to a local file; suitable for low-to-moderate traffic.
/// For high-throughput or centralized logging, replace with a queued writer or external sink.
/// </summary>
public interface IAuditLogger
{
    Task LogLoginAttemptAsync(string username, bool success, HttpContext? context = null, string? reason = null);
    Task LogLogoutAsync(string username, HttpContext? context = null);
    Task LogAccessAsync(string? username, string path, int statusCode, HttpContext? context = null);
}

public class AuditLogger : IAuditLogger
{
    private readonly string _filePath;
    private static readonly object _fileLock = new();

    public AuditLogger(IWebHostEnvironment env)
    {
        var logsDir = Path.Combine(env.ContentRootPath, "logs");
        if (!Directory.Exists(logsDir)) Directory.CreateDirectory(logsDir);
        _filePath = Path.Combine(logsDir, "auth-events.txt");
    }

    private static string TimestampUtc() => DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);

    // Basic sanitization to keep log lines single-line and remove control characters.
    private static string Sanitize(string? s) => string.IsNullOrEmpty(s) ? string.Empty : s.ReplaceLineEndings(" ").Trim();

    private string BuildEntry(string type, string username, string detail, HttpContext? ctx)
    {
        var sb = new StringBuilder();
        sb.Append('[').Append(TimestampUtc()).Append("] ");
        sb.Append(type).Append(' ');
        sb.Append("user=").Append(Sanitize(username)).Append(' ');
        sb.Append(detail);
        if (ctx != null)
        {
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
            var ua = Sanitize(ctx.Request.Headers["User-Agent"].ToString());
            sb.Append(' ').Append("ip=").Append(ip).Append(' ');
            sb.Append("ua=\"").Append(ua).Append("\"");
        }
        sb.AppendLine();
        return sb.ToString();
    }

    private Task AppendAsync(string line)
    {
        lock (_fileLock)
        {
            return File.AppendAllTextAsync(_filePath, line);
        }
    }

    public Task LogLoginAttemptAsync(string username, bool success, HttpContext? context = null, string? reason = null)
    {
        var detail = success ? "login=success" : $"login=failure reason=\"{Sanitize(reason)}\"";
        var entry = BuildEntry("AUTH", username ?? string.Empty, detail, context);
        return AppendAsync(entry);
    }

    public Task LogLogoutAsync(string username, HttpContext? context = null)
    {
        var entry = BuildEntry("AUTH", username ?? string.Empty, "logout", context);
        return AppendAsync(entry);
    }

    public Task LogAccessAsync(string? username, string path, int statusCode, HttpContext? context = null)
    {
        var detail = $"access path=\"{Sanitize(path)}\" status={statusCode}";
        var entry = BuildEntry("ACCESS", username ?? string.Empty, detail, context);
        return AppendAsync(entry);
    }
}
