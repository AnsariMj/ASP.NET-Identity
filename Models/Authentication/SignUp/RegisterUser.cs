using System.ComponentModel.DataAnnotations;

namespace UserManagement.API.Models.Authentication.SignUp;

public class RegisterUser
{
    [Required(ErrorMessage = "User Name is required")]
    public string? Username { get; set; }

    [EmailAddress]
    [Required(ErrorMessage = "Email is requred")]
    public string Email { get; set; }

    [Required(ErrorMessage = " Password is requird")]
    public string Password { get; set; }
}
