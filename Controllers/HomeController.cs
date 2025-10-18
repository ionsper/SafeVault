using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;

namespace SafeVault.Controllers;

public class HomeController : Controller
{
    [AllowAnonymous]
    public IActionResult Index()
    {
        return View();
    }

    // Handle status code pages (e.g. 404)
    [AllowAnonymous]
    public new IActionResult StatusCode(int code)
    {
        Response.StatusCode = code;

        if (code == 404)
        {
            return View("NotFound");
        }

        return View("StatusCode", code);
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [AllowAnonymous]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    // Show a friendly access denied page when authorization fails
    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        Response.StatusCode = 403;
        return View("AccessDenied");
    }
}
