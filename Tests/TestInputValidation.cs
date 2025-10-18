using System;
using System.Linq;
using System.Threading.Tasks;
// using System.Collections.Generic; (not used)
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using NUnit.Framework;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using SafeVault.Controllers;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        // Use the concrete validator implementation for tests.
        private UserValidator? _validator;

        [SetUp]
        public void SetUp()
        {
            _validator = new UserValidator();
        }

        [Test]
        public async Task TestForSQLInjection()
        {
            // Attempt a SQL injection-like payload in username and email.
            var user = new User
            {
                Username = "admin' OR '1'='1",
                Email = "attacker@example.com'"
            };

            var modelState = new ModelStateDictionary();

            // null-forgiving: SetUp initializes the validator.
            await _validator!.ValidateAsync(user, modelState);

            // Username should be rejected by the whitelist regex.
            Assert.That(modelState.ContainsKey(nameof(User.Username)), Is.True, "Expected username model state error for SQL injection-like input");
            var errors = modelState[nameof(User.Username)]!.Errors;
            Assert.That(errors, Is.Not.Empty);
        }

        [Test]
        public async Task TestForXSS()
        {
            // Attempt to inject HTML/JS into username and email.
            var user = new User
            {
                Username = "<script>alert('xss')</script>",
                Email = "<img src=x onerror=alert(1)>@example.com"
            };

            var modelState = new ModelStateDictionary();

            await _validator!.ValidateAsync(user, modelState);

            // Username should be rejected by the whitelist regex.
            Assert.That(modelState.ContainsKey(nameof(User.Username)), Is.True, "Expected username model state error for XSS-like input");
            Assert.That(modelState[nameof(User.Username)]!.Errors, Is.Not.Empty);

            // Email may be normalized; since DataAnnotations are not executed here, assert
            // the validator rejects raw HTML in the username.
        }

        [Test]
        public void Argon2Hasher_VerifyPasswords()
        {
            var hasher = new Argon2PasswordHasher();
            var user = new User { Username = "t", Email = "t@e.com" };
            var hash = hasher.HashPassword(user, "mysecretpw");

            var ok = hasher.VerifyHashedPassword(user, hash, "mysecretpw");
            Assert.That(ok, Is.EqualTo(Microsoft.AspNetCore.Identity.PasswordVerificationResult.Success));

            var bad = hasher.VerifyHashedPassword(user, hash, "wrong");
            Assert.That(bad, Is.EqualTo(Microsoft.AspNetCore.Identity.PasswordVerificationResult.Failed));
        }

        // Test authentication service used to stub SignInAsync in controller tests.
        private class TestAuthService : IAuthenticationService
        {
            public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme)
                => Task.FromResult(AuthenticateResult.NoResult());

            public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }

            public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            }

            public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
            {
                // No-op for tests: simulate a successful sign-in.
                return Task.CompletedTask;
            }

            public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
            {
                return Task.CompletedTask;
            }
        }

        // Simple in-memory TempData provider used by controller tests.
        private class TestTempDataProvider : ITempDataProvider
        {
            public IDictionary<string, object> LoadTempData(HttpContext context)
            {
                return new Dictionary<string, object>();
            }

            public void SaveTempData(HttpContext context, IDictionary<string, object> values)
            {
                // no-op for tests
            }
        }

        [Test]
        public async Task LoginController_InvalidAndValidAttempt()
        {
            // Set up an in-memory SQLite EF Core context.
            using var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();
            var opts = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseSqlite(connection)
                .Options;

            using var db = new ApplicationDbContext(opts);
            db.Database.EnsureDeleted();
            db.Database.EnsureCreated();

            var hasher = new Argon2PasswordHasher();
            var user = new User { Username = "bob", Email = "bob@example.com", Role = "User" };
            user.PasswordHash = hasher.HashPassword(user, "s3cret123");
            db.AppUsers!.Add(user);
            db.SaveChanges();

            // Instantiate controller under test.
            var controller = new LoginController(db, hasher);

            // Prepare HttpContext with a stubbed IAuthenticationService so SignInAsync is no-op.
            var services = new ServiceCollection();
            services.AddSingleton<IAuthenticationService, TestAuthService>();
            // Provide ITempData services so TempData and Controller.View() work in unit tests.
            services.AddSingleton<ITempDataProvider, TestTempDataProvider>();
            services.AddSingleton<ITempDataDictionaryFactory, TempDataDictionaryFactory>();
            var sp = services.BuildServiceProvider();

            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { RequestServices = sp }
            };

            // Ensure TempData is available for View calls.
            controller.TempData = new TempDataDictionary(controller.HttpContext, new TestTempDataProvider());
            // Provide a simple UrlHelper so RedirectToAction/Url work in unit tests.
            controller.Url = new Microsoft.AspNetCore.Mvc.Routing.UrlHelper(
                new Microsoft.AspNetCore.Mvc.ActionContext(
                    controller.HttpContext,
                    new Microsoft.AspNetCore.Routing.RouteData(),
                    new Microsoft.AspNetCore.Mvc.Abstractions.ActionDescriptor()));

            // Invalid credential attempt.
            var invalidModel = new User { Username = "bob", Password = "wrongpw" };
            var invalidResult = await controller.Login(invalidModel) as ViewResult;
            Assert.That(invalidResult, Is.Not.Null);
            Assert.That(controller.ViewData.ContainsKey("Error"), Is.True);

            // Valid credential attempt.
            var validModel = new User { Username = "bob", Password = "s3cret123" };
            var validResult = await controller.Login(validModel) as RedirectToActionResult;
            Assert.That(validResult, Is.Not.Null);
            Assert.That(validResult!.ActionName, Is.EqualTo("Index"));
            Assert.That(validResult.ControllerName, Is.EqualTo("Home"));
        }

        [Test]
        public async Task AdminController_AuthorizationAndRoleBasedBehavior()
        {
            var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();
            var opts = new DbContextOptionsBuilder<ApplicationDbContext>()
                .UseSqlite(connection)
                .Options;

            using var db = new ApplicationDbContext(opts);
            db.Database.EnsureDeleted();
            db.Database.EnsureCreated();

            db.AppUsers!.Add(new User { Username = "u1", Email = "u1@example.com", Role = "User" });
            db.AppUsers!.Add(new User { Username = "u2", Email = "u2@example.com", Role = "User" });
            db.SaveChanges();

            // Verify AdminController is decorated with Authorize(Roles = "Admin").
            var attr = typeof(AdminController).GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), inherit: true)
                .Cast<Microsoft.AspNetCore.Authorization.AuthorizeAttribute>()
                .FirstOrDefault();
            Assert.That(attr, Is.Not.Null);
            Assert.That(attr!.Roles, Is.EqualTo("Admin"));

            var controller = new AdminController(db);

            // Simulate a non-admin user context.
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "u1"), new Claim(ClaimTypes.Role, "User") }, "Test")) }
            };

            // Ensure the controller principal exists and verify the role.
            Assert.That(controller.User, Is.Not.Null);
            Assert.That(controller.User.IsInRole("Admin"), Is.False);

            // Simulate an admin user and call Dashboard action.
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "admin"), new Claim(ClaimTypes.Role, "Admin") }, "Test")) }
            };

            var result = await controller.Dashboard() as ViewResult;
            Assert.That(result, Is.Not.Null);
            Assert.That(result!.Model, Is.InstanceOf<System.Collections.IEnumerable>());
        }
    }
}
