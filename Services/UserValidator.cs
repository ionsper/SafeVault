using System.Text.RegularExpressions;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using SafeVault.Models;

namespace SafeVault.Services;

public class UserValidator : IUserValidator
{
    // Username whitelist: letters, numbers, underscore, dot and hyphen. Length and
    // other constraints are enforced by model DataAnnotations where applicable.
    private static readonly Regex UsernamePattern = new(@"^[A-Za-z0-9_.-]{3,50}$", RegexOptions.Compiled);

    public Task ValidateAsync(User user, ModelStateDictionary modelState)
    {
        if (user == null)
        {
            modelState.AddModelError(string.Empty, "User is required.");
            return Task.CompletedTask;
        }

        // Trim and normalize input values in-place.
        user.Username = user.Username?.Trim();
        user.Email = user.Email?.Trim();

        // Username: enforce required, pattern and length constraints.
        if (string.IsNullOrEmpty(user.Username))
        {
            modelState.AddModelError(nameof(User.Username), "Username is required.");
        }
        else if (!UsernamePattern.IsMatch(user.Username))
        {
            modelState.AddModelError(nameof(User.Username), "Username may only contain letters, numbers, ., _, - and must be 3-50 characters.");
        }

        // Email: enforce required, max length and basic format validation.
        if (string.IsNullOrEmpty(user.Email))
        {
            modelState.AddModelError(nameof(User.Email), "Email is required.");
        }
        else
        {
            if (user.Email.Length > 254)
            {
                modelState.AddModelError(nameof(User.Email), "Email must not exceed 254 characters.");
            }

            var emailAttr = new EmailAddressAttribute();
            if (!emailAttr.IsValid(user.Email))
            {
                modelState.AddModelError(nameof(User.Email), "Invalid email address.");
            }
            else
            {
                user.Email = user.Email.ToLowerInvariant();
            }
        }

        // Password: require and validate length for transient password property (not persisted).
        if (string.IsNullOrEmpty(user.Password))
        {
            modelState.AddModelError(nameof(User.Password), "Password is required.");
        }
        else if (user.Password.Length < 8 || user.Password.Length > 100)
        {
            modelState.AddModelError(nameof(User.Password), "Password must be at least 8 characters and at most 100 characters.");
        }

        return Task.CompletedTask;
    }
}
