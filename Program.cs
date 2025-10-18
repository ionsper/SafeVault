using SafeVault.Middleware;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.IO;
using System;

var builder = WebApplication.CreateBuilder(args);

// Configure services and application dependencies.
// Add MVC and enforce HTTPS for all controllers/actions by default.
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new RequireHttpsAttribute());
});

// Configure HSTS for production scenarios and HTTPS redirection options.
builder.Services.AddHsts(options =>
{
    // For production, a long max-age is recommended. During development this has no effect.
    options.Preload = true;
    options.IncludeSubDomains = true;
    options.MaxAge = TimeSpan.FromDays(365);
});

builder.Services.AddHttpsRedirection(options =>
{
    // Use 308 Permanent Redirect so the HTTP method is preserved.
    options.RedirectStatusCode = StatusCodes.Status308PermanentRedirect;
    // Local dev HTTPS port (matches launchSettings.json).
    options.HttpsPort = 7000;
});
// Register application services and implementations for dependency injection
builder.Services.AddSingleton<SafeVault.Services.IUserValidator, SafeVault.Services.UserValidator>();
// Configure Entity Framework Core to use SQLite. Ensure the configured Data Source path
// points to a file under the application's content root so the DB file is stored with the app.
var configured = builder.Configuration.GetConnectionString("Default");
string connectionString;
if (!string.IsNullOrWhiteSpace(configured))
{
    // If the configured connection string uses the simple "Data Source=<path>" form and the
    // path is relative, convert it to an absolute path under the content root so the DB file
    // is created next to the application files.
    const string prefix = "Data Source=";
    if (configured.StartsWith(prefix, System.StringComparison.OrdinalIgnoreCase))
    {
        var ds = configured.Substring(prefix.Length);
        if (!Path.IsPathRooted(ds)) ds = Path.Combine(builder.Environment.ContentRootPath, ds);
        connectionString = $"Data Source={ds}";
    }
    else
    {
        connectionString = configured;
    }
}
else
{
    var dbPath = Path.Combine(builder.Environment.ContentRootPath, "app.db");
    connectionString = $"Data Source={dbPath}";
}

builder.Services.AddDbContext<SafeVault.Data.ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));

// Register an Argon2-based IPasswordHasher<User> implementation for secure password hashing.
builder.Services.AddScoped<Microsoft.AspNetCore.Identity.IPasswordHasher<SafeVault.Models.User>, SafeVault.Services.Argon2PasswordHasher>();

// Register audit logger for authentication and access events
builder.Services.AddSingleton<SafeVault.Services.IAuditLogger, SafeVault.Services.AuditLogger>();

// Configure cookie-based authentication scheme and options.
builder.Services.AddAuthentication("SafeVaultCookie")
    .AddCookie("SafeVaultCookie", options =>
    {
        options.LoginPath = "/Login/Login";
        options.AccessDeniedPath = "/Home/AccessDenied";
        options.Cookie.Name = "SafeVault.Auth";
        options.Cookie.HttpOnly = true;
        // Ensure cookies are only sent over HTTPS.
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        // Reasonable default for SameSite to help mitigate CSRF in browsers while allowing top-level POSTs.
        options.Cookie.SameSite = SameSiteMode.Lax;
        // Expire session cookies after a reasonable period and enable sliding expiration.
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });


var app = builder.Build();

// Ensure the SQLite database file exists and the schema is created at startup. This will create
// the database file at the resolved path when the application runs for the first time.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SafeVault.Data.ApplicationDbContext>();
    db.Database.EnsureCreated();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    // In Development, show the developer exception page with detailed diagnostics.
    app.UseDeveloperExceptionPage();
}
else
{
    // In non-development environments, use a user-friendly error handler to avoid leaking internal details.
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. Adjust this for longer-lived production deployments as needed.
    app.UseHsts();
}

// Register the file-based exception logging middleware after the built-in exception handler so
// it can read the IExceptionHandlerFeature and include exception details in the application log.
app.UseExceptionFileLogging();

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Log authenticated access events to a separate file
app.UseAuditLogging();

// Re-execute the pipeline for HTTP status code responses to render friendly status pages (e.g. 404).
// Place this after UseAuthorization and before endpoint mapping so status pages render correctly.
app.UseStatusCodePagesWithReExecute("/Home/StatusCode", "?code={0}");

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();
