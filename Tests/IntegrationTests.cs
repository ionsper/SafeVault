using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;

namespace SafeVault.Tests
{
    [TestFixture]
    public class IntegrationTests
    {
        [Test]
        public async Task InvalidLogin_ShowsErrorMessage()
        {
            using var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();
            var opts = new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connection).Options;

            using var db = new ApplicationDbContext(opts);
            db.Database.EnsureCreated();

            var hasher = new Argon2PasswordHasher();
            var user = new User { Username = "regular", Email = "user@example.com", Role = "User" };
            user.PasswordHash = hasher.HashPassword(user, "password123");
            db.AppUsers!.Add(user);
            db.SaveChanges();

            var controller = new LoginController(db, hasher);

            var model = new User { Username = "regular", Password = "wrongpassword" };
            var result = await controller.Login(model) as ViewResult;

            Assert.That(result, Is.Not.Null);
            Assert.That(controller.ViewData.ContainsKey("Error"), Is.True);
        }

        [Test]
        public async Task AdminController_HasAuthorizeAttribute_And_AdminCanAccess()
        {
            using var connection = new SqliteConnection("DataSource=:memory:");
            connection.Open();
            var opts = new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(connection).Options;

            using var db = new ApplicationDbContext(opts);
            db.Database.EnsureCreated();

            db.AppUsers!.Add(new User { Username = "u1", Email = "u1@example.com", Role = "User" });
            db.AppUsers!.Add(new User { Username = "admin", Email = "admin@example.com", Role = "Admin" });
            db.SaveChanges();

            var attr = typeof(AdminController).GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true)
                .Cast<AuthorizeAttribute>()
                .FirstOrDefault();
            Assert.That(attr, Is.Not.Null);
            Assert.That(attr!.Roles, Is.EqualTo("Admin"));

            var controller = new AdminController(db);

            // Simulate a non-admin principal.
            controller.ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "u1"), new Claim(ClaimTypes.Role, "User") }, "Test")) }
            };

            Assert.That(controller.User, Is.Not.Null);
            Assert.That(controller.User.IsInRole("Admin"), Is.False);

            // Simulate an admin principal.
            controller.ControllerContext = new Microsoft.AspNetCore.Mvc.ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "admin"), new Claim(ClaimTypes.Role, "Admin") }, "Test")) }
            };

            var view = await controller.Dashboard() as ViewResult;
            Assert.That(view, Is.Not.Null);
            Assert.That(view!.Model, Is.InstanceOf<System.Collections.IEnumerable>());
        }
    }
}

