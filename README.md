# SafeVault

SafeVault is a small ASP.NET Core MVC sample application that demonstrates practical security and authentication topics for learning and experimentation. The project highlights secure password hashing (Argon2id), cookie-based authentication, middleware-driven audit logging, and file-based exception logging.

This project is an assignment for the course: Security and Authentication by Microsoft on Coursera.

## Quick overview

- Framework: .NET 9 (net9.0)
- Application type: ASP.NET Core MVC (Razor views)
- Persistence: SQLite via Entity Framework Core (file `app.db` by default)
- Password hashing: Argon2id using `Isopoh.Cryptography.Argon2` (see `Services/Argon2PasswordHasher.cs`)
- Audit & error logs: files under the `logs/` directory (`auth-events.txt`, `errors.txt`)

## Features

- User registration and login with server-side validation (see `Controllers/` and `Views/`).
- Secure password hashing (Argon2id) via a custom `IPasswordHasher<User>` implementation.
- Cookie-based authentication configured with secure cookie settings.
- Audit logging of authentication and access events to `logs/auth-events.txt`.
- File-based exception and HTTP error logging to `logs/errors.txt`.
- Simple EF Core setup using SQLite; the database file is created automatically on startup.

## Prerequisites

- Install the .NET 9 SDK: [Download .NET 9 SDK](https://dotnet.microsoft.com/download)
- A terminal (PowerShell is used in examples below)

## Run (development)

Open PowerShell in the project root (the folder that contains `SafeVault.csproj`) and run:

```powershell
dotnet restore; dotnet run
```

Notes:

- The app redirects HTTP to HTTPS; development HTTPS port matches `launchSettings.json` (default 7000).
- On first run the SQLite database file (default `app.db`) will be created automatically in the content root.

## Build and test

Build the project:

```powershell
dotnet build
```

Run tests:

```powershell
dotnet test
```

You can filter tests or run a single test class using the `--filter` option supported by `dotnet test`.

## Configuration

- Application configuration files: `appsettings.json` and `appsettings.Development.json`.
- Connection string name: `Default`. If no connection string is present the app uses `app.db` in the content root.
- Cookie authentication scheme: `SafeVaultCookie` (see `Program.cs`). Cookies are configured with `HttpOnly`, `Secure`, and `SameSite=Lax`.

## Security notes (important)

- This project is educational. Do NOT use the demo authentication mechanisms or any hard-coded tokens in production.
- The Argon2 parameters in `Services/Argon2PasswordHasher.cs` are conservative and intended for demonstration; for production, benchmark and tune memory and time cost on representative hardware.
- Log files under `logs/` may contain sensitive information (IP addresses, user-agents, usernames). Keep them local and protect access.

## Project structure highlights

- `Program.cs` — app startup, DI registration, middleware pipeline.
- `Services/Argon2PasswordHasher.cs` — Argon2id password hasher implementing `IPasswordHasher<User>`.
- `Services/AuditLogger.cs` — simple file-based audit logging implementation.
- `Middleware/` — `AuditLoggingMiddleware` and `ExceptionLoggingMiddleware`.
- `Data/ApplicationDbContext.cs` — EF Core DbContext using SQLite.
- `Controllers/`, `Views/` — MVC controllers and Razor views for UI.

## Development tips

- To reset the database during development, stop the app and delete `app.db` (or the path configured in your connection string). The schema is created automatically on next startup.
- To inspect log entries, open files in `logs/` (`auth-events.txt`, `errors.txt`).

## Contributing

This repository is part of an educational course. If you'd like to suggest improvements, open an issue or a pull request describing the change.


## Folder/File structure

```
└── 📁SafeVault
    └── 📁Controllers
        ├── AdminController.cs
        ├── HomeController.cs
        ├── LoginController.cs
        ├── ProfileController.cs
        ├── RegisterController.cs
        ├── UsersController.cs
    └── 📁Data
        ├── ApplicationDbContext.cs
    └── 📁logs
        ├── auth-events.txt
        ├── errors.txt
    └── 📁Middleware
        ├── AuditLoggingMiddleware.cs
        ├── ExceptionLoggingMiddleware.cs
    └── 📁Models
        ├── ErrorViewModel.cs
        ├── User.cs
    └── 📁Properties
        ├── launchSettings.json
    └── 📁Services
        ├── Argon2PasswordHasher.cs
        ├── AuditLogger.cs
        ├── IUserValidator.cs
        ├── UserValidator.cs
    └── 📁Tests
        ├── IntegrationTests.cs
        ├── TestInputValidation.cs
    └── 📁Views
        └── 📁Home
            ├── AccessDenied.cshtml
            ├── Index.cshtml
            ├── NotFound.cshtml
            ├── StatusCode.cshtml
        └── 📁Management
            ├── AdminDashboard.cshtml
        └── 📁Shared
            ├── _Layout.cshtml
            ├── _Layout.cshtml.css
            ├── _ValidationScriptsPartial.cshtml
            ├── Error.cshtml
        └── 📁Users
            ├── Login.cshtml
            ├── Profile.cshtml
            ├── Register.cshtml
        ├── _ViewImports.cshtml
        ├── _ViewStart.cshtml
    └── 📁wwwroot
        └── 📁css
            ├── site.css
        └── 📁js
            ├── site.js
        └── 📁lib
            └── 📁bootstrap
                ├── LICENSE
            └── 📁jquery
                ├── LICENSE.txt
            └── 📁jquery-validation
                ├── LICENSE.md
            └── 📁jquery-validation-unobtrusive
                ├── LICENSE.txt
        ├── favicon.ico
    ├── 14. SafeVault.csproj
    ├── 14. SafeVault.sln
    ├── app.db
    ├── appsettings.Development.json
    ├── appsettings.json
    ├── Program.cs
    └── README.md
```

---

## License

This project is open source and available under the MIT License.

---
