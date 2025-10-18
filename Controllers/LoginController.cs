using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Controllers
{
    public class LoginController : Controller
    {
        private readonly SafeVault.Data.ApplicationDbContext _db;
        private readonly Microsoft.AspNetCore.Identity.IPasswordHasher<User> _hasher;
        private readonly SafeVault.Services.IAuditLogger? _audit;

        public LoginController(SafeVault.Data.ApplicationDbContext db, Microsoft.AspNetCore.Identity.IPasswordHasher<User> hasher, SafeVault.Services.IAuditLogger? audit = null)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
            _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
            _audit = audit;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login()
        {
            // Render the login view with an empty model for binding.
            return View("~/Views/Users/Login.cshtml", new User());
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(User model)
        {
            if (string.IsNullOrWhiteSpace(model.Username) || string.IsNullOrWhiteSpace(model.Password))
            {
                if (_audit != null) await _audit.LogLoginAttemptAsync(model.Username ?? string.Empty, false, HttpContext, "missing credentials");
                ViewData["Error"] = "Please provide username and password.";
                return View("~/Views/Users/Login.cshtml", model);
            }
            // Normalize username for lookup to avoid case-sensitive enumeration differences.
            var normalizedUsername = model.Username.Trim();

            var usersSet = _db.AppUsers ?? _db.Set<User>();
            var user = await usersSet.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user is null)
            {
                if (_audit != null) await _audit.LogLoginAttemptAsync(normalizedUsername, false, HttpContext, "invalid credentials");
                ViewData["Error"] = "Invalid username or password.";
                return View("~/Views/Users/Login.cshtml", model);
            }

            var result = _hasher.VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, model.Password);
            if (result == Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success)
            {
                // Create a simple ClaimsPrincipal and sign in using cookie authentication
                var claims = new[] {
                    new Claim(ClaimTypes.Name, normalizedUsername),
                    new Claim(ClaimTypes.Role, user?.Role ?? "User")
                };
                var identity = new ClaimsIdentity(claims, "SafeVaultCookie");
                var principal = new ClaimsPrincipal(identity);

                // Prevent session fixation by ensuring any existing authentication is cleared before sign-in.
                await HttpContext.SignOutAsync("SafeVaultCookie");
                await HttpContext.SignInAsync("SafeVaultCookie", principal);

                if (_audit != null) await _audit.LogLoginAttemptAsync(normalizedUsername, true, HttpContext);
                // On successful sign-in redirect to home (avoid showing login view after sign-in)
                return RedirectToAction("Index", "Home");
            }

            if (_audit != null) await _audit.LogLoginAttemptAsync(normalizedUsername, false, HttpContext, "invalid credentials");
            ViewData["Error"] = "Invalid username or password.";
            return View("~/Views/Users/Login.cshtml", model);
        }
        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var username = User?.Identity?.Name ?? string.Empty;
            await HttpContext.SignOutAsync("SafeVaultCookie");
            if (_audit != null) await _audit.LogLogoutAsync(username, HttpContext);
            return RedirectToAction("Index", "Home");
        }
    }
}
