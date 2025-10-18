using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers;

public class UsersController : Controller
{

    private readonly IUserValidator _validator;

    public UsersController(IUserValidator validator)
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Register()
    {
        return View("Register");
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Submit()
    {
        var form = await Request.ReadFormAsync();
        var username = form["username"].ToString();
        var email = form["email"].ToString();

        var user = new User { Username = username, Email = email };

        // Normalize inputs and run additional validation via the injected IUserValidator (adds ModelState errors).
        await _validator.ValidateAsync(user, ModelState);

        // Validate the constructed model using DataAnnotations and ModelState.
        if (!TryValidateModel(user) || !ModelState.IsValid)
        {
            return View("Register", user);
        }



        // On success: clear the form and display a success banner on the Register view.
        ModelState.Clear();
        ViewData["Success"] = $"Created user {user.Username} with email {user.Email}";
        return View("Register", new User());
    }
}
