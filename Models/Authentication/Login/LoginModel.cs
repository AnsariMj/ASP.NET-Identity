using System.ComponentModel.DataAnnotations;

namespace UserManagement.API.Models.Authentication.Login
{
    public class LoginModel
    {
        [Required(ErrorMessage = "User Name is required")]
        public string? Username { get; set; }

        [Required(ErrorMessage = " Password is requird")]
        public string? Password { get; set; }
    }
}
