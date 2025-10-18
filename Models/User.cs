namespace SafeVault.Models;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class User
{
    public int UserID { get; set; }   // Database primary key; assigned by the database on insert.

    [Required(ErrorMessage = "Username is required.")]
    [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters.")]
    public string? Username { get; set; }

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    [StringLength(254, ErrorMessage = "Email must not exceed 254 characters.")]
    public string? Email { get; set; }

    // Transient plaintext password used only for model binding/validation during
    // registration or authentication. Do not persist this property.
    [NotMapped]
    [DataType(DataType.Password)]
    [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters.")]
    public string? Password { get; set; }

    // Persisted encoded password hash. Store only the hashed value produced by a
    // secure password hasher (for example, an IPasswordHasher<TUser> implementation).
    public string? PasswordHash { get; set; }

    [RegularExpression("^(Admin|User)$", ErrorMessage = "Role must be either 'Admin' or 'User'.")]
    public string Role { get; set; } = "User";
}
