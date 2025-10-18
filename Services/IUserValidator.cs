using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using SafeVault.Models;

namespace SafeVault.Services;

public interface IUserValidator
{
    /// <summary>
    /// Validate and optionally normalize a <see cref="SafeVault.Models.User"/> instance.
    /// Validation failures must be reported by adding entries to the provided
    /// <see cref="Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary"/>; implementations
    /// should not throw for validation errors.
    /// </summary>
    Task ValidateAsync(User user, ModelStateDictionary modelState);
}
