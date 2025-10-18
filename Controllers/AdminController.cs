using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly SafeVault.Data.ApplicationDbContext _db;

        public AdminController(SafeVault.Data.ApplicationDbContext db)
        {
            _db = db ?? throw new ArgumentNullException(nameof(db));
        }

        // GET: /Admin/Dashboard
        public async Task<IActionResult> Dashboard()
        {
            var users = await (_db.AppUsers ?? _db.Set<User>())
                .Where(u => u.Role == "User")
                .AsNoTracking()
                .ToListAsync();

            return View("~/Views/Management/AdminDashboard.cshtml", users);
        }

        // POST: /Admin/DeleteUser
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var set = _db.AppUsers ?? _db.Set<User>();
            var u = await set.FindAsync(id);
            if (u is null)
            {
                return NotFound();
            }

            set.Remove(u);
            await _db.SaveChangesAsync();

            return RedirectToAction("Dashboard");
        }
    }
}
