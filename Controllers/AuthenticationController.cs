using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserManagement.API.Models.Authentication.SignUp;
using UserManagement.API.Models.Authentication;
using User.Management.Service.Services;
using User.Management.Service.Models;
using Org.BouncyCastle.Ocsp;
using UserManagement.API.Models.Authentication.Login;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;

namespace UserManagement.API.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly IConfiguration _configuration;
    private readonly IEmailService _emailService;
    public AuthenticationController(
        UserManager<IdentityUser> userManager,
        RoleManager<IdentityRole> roleManager,
        SignInManager<IdentityUser> signInManager,
        IConfiguration configuration,
        IEmailService emailService
        )
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _emailService = emailService;
    }


    // Add New Users
    [HttpPost]
    public async Task<IActionResult> Rsgister([FromBody] RegisterUser registerUser, string role)
    {
        // Check User Exists
        var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
        if (userExist != null)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User Already Exists" });
        }
        //Add the user in Db
        IdentityUser user = new()
        {
            Email = registerUser.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = registerUser.Username,
            TwoFactorEnabled = true
        };
        if (await _roleManager.RoleExistsAsync(role))
        {
            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (!result.Succeeded)
            {
                //   return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Fail to Create User" });
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = $"Fail to Create User: {errors}" });
            }
            //Add Role to the user
            await _userManager.AddToRoleAsync(user, role);

            //Add Token to Verify the email..
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);
            var message = new Message(new string[] { user.Email }, "Confirmation email link", confirmationLink!);
            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "User Created Successfully" });
        }
        else
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "This Role Does't Exist!" });
        }
    }

    //Login 
    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
    {
        //Checking the User Exist
        var user = await _userManager.FindByNameAsync(loginModel.Username);

        if (user.TwoFactorEnabled)
        {
            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

            var otp = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

            var message = new Message(new string[] { user.Email! }, "Login Confirmation OTP", otp!);
            _emailService.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"We Have Send to an OTP to your Email: {user.Email}" });
        }
        //Checking valid Password
        if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
        {
            //claimlist creation
            var authClaim = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
            var userRoles = await _userManager.GetRolesAsync(user);

            //add roles to the list
            foreach (var role in userRoles)
            {
                authClaim.Add(new Claim(ClaimTypes.Role, role));
            }

            //generate token with claims
            var jwtToken = GetToken(authClaim);

            //returning the token
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                expiration = jwtToken.ValidTo
            });
        }
        return Unauthorized();
    }

    //Login With OTP
    [HttpPost]
    [Route("login-2FA")]
    public async Task<IActionResult> LoginWithOTP(string code, string username)
    {
        var user = await _userManager.FindByNameAsync(username);
        var singIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
        if (singIn.Succeeded)
        {
            //Checking valid Password
            if (user != null)
            {
                //claimlist creation
                var authClaim = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
                var userRoles = await _userManager.GetRolesAsync(user);

                //add roles to the list
                foreach (var role in userRoles)
                {
                    authClaim.Add(new Claim(ClaimTypes.Role, role));
                }

                //generate token with claims
                var jwtToken = GetToken(authClaim);

                //returning the token
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                });
            }

        }
        return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Success", Message = $"Invalid Code" });
    }

    //Forget Password 
    [HttpPost]
    [AllowAnonymous]
    [Route("forgot-password")]
    public async Task<IActionResult> ForgetPassword(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var forgetPasswordlink = Url.Action(nameof(ResetPasswordTokenLink), "Authentication", new { token, email = user.Email }, Request.Scheme);
            var message = new Message(new string[] { user.Email }, "Forget Password link", forgetPasswordlink!);
            _emailService.SendEmail(message);

            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"Pssword Rest Link is sent to {user.Email}  Please Verify Your Email reset your password" });
        }
        return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "Please Enter corret email and try again!" });
    }

    //Reset Password 
    [HttpPost]
    [AllowAnonymous]
    [Route("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
    {
        var user = await _userManager.FindByEmailAsync(resetPassword.Email);
        if (user != null)
        {
            var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
            if (!resetPassResult.Succeeded)
            {
                foreach (var error in resetPassResult.Errors)
                {
                    ModelState.AddModelError(error.Code, error.Description);
                }
                return Ok(ModelState);
            }

            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"Pssword has been change successfully" });
        }
        return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = "Please enter corret email and try again!" });
    }

    //Sending Email 
    [HttpGet]
    public IActionResult TestEmail()
    {
        var message = new Message(new string[] { "ansarimj17@gmail.com" }, ".Net Mail Checking Server", "This Email is for testing prupose only 😊 ");
        _emailService.SendEmail(message);
        return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email Send Successfully" });
    }

    //Verifying Email by sending link to Registered Email
    [HttpGet("ConfirmEmail")]
    public async Task<IActionResult> ConfirmEmail(string token, string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email Verified Succesfully " });
            }
        }
        return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Does't exists!" });
    }

    //Generatig JWT Token
    private JwtSecurityToken GetToken(List<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var token = new JwtSecurityToken(

            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );
        return token;
    }

    [HttpGet("reset-password")]
    public async Task<IActionResult> ResetPasswordTokenLink(string token, string email)
    {
        var model = new ResetPassword { Token = token, Email = email };
        return Ok(new { model });
    }
}