using System;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers;

public class RegisterController : Controller
{
    private readonly IUserValidator _validator;
    private readonly SafeVault.Data.ApplicationDbContext _db;
    private readonly Microsoft.AspNetCore.Identity.IPasswordHasher<User> _hasher;
    private readonly SafeVault.Services.IAuditLogger? _audit;

    public RegisterController(IUserValidator validator, SafeVault.Data.ApplicationDbContext db, Microsoft.AspNetCore.Identity.IPasswordHasher<User> hasher, SafeVault.Services.IAuditLogger? audit = null)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
        _audit = audit;
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register()
    {
        // Render the registration view located at Views/Users/Register.cshtml.
        return View("~/Views/Users/Register.cshtml");
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Submit()
    {
        var form = await Request.ReadFormAsync();
        var username = form["username"].ToString()?.Trim();
        var email = form["email"].ToString()?.Trim();
        var password = form["Password"].ToString();
        var confirm = form["ConfirmPassword"].ToString();

        var user = new User { Username = username, Email = email, Password = password };

        // Verify that the provided password and confirmation match.
        if (!string.Equals(password ?? string.Empty, confirm ?? string.Empty, StringComparison.Ordinal))
        {
            ModelState.AddModelError("Password", "Passwords do not match.");
            ModelState.AddModelError("ConfirmPassword", "Passwords do not match.");
        }

        // Normalize inputs and run additional validation via the injected IUserValidator (adds ModelState errors).
        await _validator.ValidateAsync(user, ModelState);

        // Validate the constructed model with DataAnnotations and current ModelState.
        if (!TryValidateModel(user) || !ModelState.IsValid)
        {
            // Clear transient password data before returning the view to avoid echoing it.
            user.Password = null;
            ModelState.Remove("Password");
            return View("~/Views/Users/Register.cshtml", user);
        }

        // Server-side uniqueness checks for Username and Email.
        var usersSet = _db.AppUsers ?? _db.Set<SafeVault.Models.User>();
        // Use case-insensitive comparisons for uniqueness to prevent duplicate accounts differing only by case.
        var usernameExists = await usersSet.AnyAsync(u => (u.Username ?? string.Empty).ToLower() == (user.Username ?? string.Empty).ToLower());
        if (usernameExists)
        {
            ModelState.AddModelError(nameof(user.Username), "Username is already taken.");
        }
        var emailExists = await usersSet.AnyAsync(u => (u.Email ?? string.Empty).ToLower() == (user.Email ?? string.Empty).ToLower());
        if (emailExists)
        {
            ModelState.AddModelError(nameof(user.Email), "Email is already registered.");
        }
        if (!ModelState.IsValid)
        {
            user.Password = null;
            ModelState.Remove("Password");
            return View("~/Views/Users/Register.cshtml", user);
        }

        // On success: persist the new user. Hash the password before storage and do not persist the plain Password value.
        // Hash the password and clear the transient password field before persistence.
        user.PasswordHash = _hasher.HashPassword(user, password!);
        user.Password = null;

        // Ensure the database schema exists and add the new user entity.
        await _db.Database.EnsureCreatedAsync();
        if (_db.AppUsers is not null)
        {
            _db.AppUsers.Add(user);
        }
        else
        {
            // Fallback to generic Add if the strongly-typed AppUsers DbSet is null.
            _db.Add(user);
        }

        try
        {
            await _db.SaveChangesAsync();
            ModelState.Clear();
            if (_audit != null) await _audit.LogLoginAttemptAsync(user.Username ?? string.Empty, true, HttpContext, "registration");
            ViewData["Success"] = $"Created user {user.Username} with email {user.Email}";
            return View("~/Views/Users/Register.cshtml", new User());
        }
        catch (Microsoft.EntityFrameworkCore.DbUpdateException dbEx)
        {
            // If the database indicates a unique constraint violation, provide a friendly message.
            var msg = "Unable to create user due to a database error.";
            if (dbEx.InnerException?.Message != null && dbEx.InnerException.Message.Contains("UNIQUE constraint failed", StringComparison.OrdinalIgnoreCase))
            {
                msg = "A user with that username or email already exists.";
            }
            ModelState.AddModelError(string.Empty, msg);

            // Clear sensitive fields before returning the view.
            user.Password = null;
            ModelState.Remove("Password");
            return View("~/Views/Users/Register.cshtml", user);
        }
        catch (Exception)
        {
            // Generic failure: report a non-specific error and rely on middleware for exception logging.
            ModelState.AddModelError(string.Empty, "An unexpected error occurred while creating the user. Please try again.");

            user.Password = null;
            ModelState.Remove("Password");
            return View("~/Views/Users/Register.cshtml", user);
        }
    }
}
