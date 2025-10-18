using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using SafeVault.Models;

namespace SafeVault.Controllers;

[Authorize]
public class ProfileController : Controller
{
    private readonly SafeVault.Data.ApplicationDbContext _db;
    private readonly Microsoft.AspNetCore.Identity.IPasswordHasher<User> _hasher;

    public ProfileController(SafeVault.Data.ApplicationDbContext db, Microsoft.AspNetCore.Identity.IPasswordHasher<User> hasher)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
    }

    // GET: /Profile
    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username)) return Challenge();

        var user = await (_db.AppUsers ?? _db.Set<User>())
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Username == username);

        if (user is null) return NotFound();

        var vm = new ProfileUpdateViewModel
        {
            Username = user.Username,
            Email = user.Email
        };

        return View("~/Views/Users/Profile.cshtml", vm);
    }

    // POST: /Profile/Update
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Update(ProfileUpdateViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View("~/Views/Users/Profile.cshtml", model);
        }

        var username = User.Identity?.Name;
        if (string.IsNullOrEmpty(username)) return Challenge();

        var set = _db.AppUsers ?? _db.Set<User>();
        var user = await set.FirstOrDefaultAsync(u => u.Username == username);
        if (user is null) return NotFound();

        // Verify the user's current password before applying any profile changes.
        if (string.IsNullOrEmpty(model.CurrentPassword) ||
            _hasher.VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, model.CurrentPassword) != Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success)
        {
            ModelState.AddModelError(string.Empty, "Current password is incorrect.");
            return View("~/Views/Users/Profile.cshtml", model);
        }

        // When username or email changed, ensure uniqueness before updating.
        if (!string.Equals(user.Username, model.Username, StringComparison.Ordinal))
        {
            var exists = await set.AnyAsync(u => u.Username == model.Username && u.UserID != user.UserID);
            if (exists)
            {
                ModelState.AddModelError(nameof(model.Username), "Username is already taken.");
                return View("~/Views/Users/Profile.cshtml", model);
            }
            user.Username = model.Username;
        }

        if (!string.Equals(user.Email, model.Email, StringComparison.OrdinalIgnoreCase))
        {
            var exists = await set.AnyAsync(u => u.Email == model.Email && u.UserID != user.UserID);
            if (exists)
            {
                ModelState.AddModelError(nameof(model.Email), "Email is already registered.");
                return View("~/Views/Users/Profile.cshtml", model);
            }
            user.Email = model.Email;
        }

        // If a new password is provided, validate its length and update the stored hash.
        if (!string.IsNullOrEmpty(model.NewPassword))
        {
            if (model.NewPassword.Length < 8)
            {
                ModelState.AddModelError(nameof(model.NewPassword), "Password must be at least 8 characters.");
                return View("~/Views/Users/Profile.cshtml", model);
            }

            user.PasswordHash = _hasher.HashPassword(user, model.NewPassword);
        }

        // Persist changes to the database.
        try
        {
            await _db.SaveChangesAsync();
            ViewData["Success"] = "Profile updated successfully.";
            // If the username changed, sign the user out so they can re-authenticate with the updated identity.
            if (User.Identity?.Name != user.Username)
            {
                await HttpContext.SignOutAsync("SafeVaultCookie");
                return RedirectToAction("Login", "Login");
            }
            // Return the updated profile view.
            var vm = new ProfileUpdateViewModel { Username = user.Username, Email = user.Email };
            return View("~/Views/Users/Profile.cshtml", vm);
        }
        catch (DbUpdateException)
        {
            ModelState.AddModelError(string.Empty, "Unable to update profile due to a database error.");
            return View("~/Views/Users/Profile.cshtml", model);
        }
    }

    public class ProfileUpdateViewModel
    {
        [System.ComponentModel.DataAnnotations.Required]
        [System.ComponentModel.DataAnnotations.StringLength(50, MinimumLength = 3)]
        public string? Username { get; set; }

        [System.ComponentModel.DataAnnotations.Required]
        [System.ComponentModel.DataAnnotations.EmailAddress]
        [System.ComponentModel.DataAnnotations.StringLength(254)]
        public string? Email { get; set; }

        [System.ComponentModel.DataAnnotations.DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        public string? CurrentPassword { get; set; }

        [System.ComponentModel.DataAnnotations.DataType(System.ComponentModel.DataAnnotations.DataType.Password)]
        public string? NewPassword { get; set; }
    }
}
