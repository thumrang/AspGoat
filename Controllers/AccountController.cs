using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace AspGoat.Controllers
{
    public class AccountController : Controller
    {
        // Single default user
        private readonly string defaultUsername = "admin";
        private readonly string defaultPassword = "admin123";
        private readonly string defaultRole = "Admin";

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password, string? returnUrl = null)
        {
            if (username == defaultUsername && password == defaultPassword)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim(ClaimTypes.Role, defaultRole)
                };

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

                return Redirect(returnUrl ?? "/Home/Dashboard");
            }

            ViewData["Error"] = "Invalid username or password.";
            return View();
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return Content("POST a 'username' to generate a password reset code.");
        }

        [HttpPost]
        public IActionResult ForgotPassword(string username)
        {
            // Vulnerable: the reset code is generated from a
            // millisecond-of-the-current-second seeded PRNG rather than a
            // cryptographically secure random source (e.g.
            // RandomNumberGenerator). The seed space is narrow (0-999),
            // making the resulting 6-digit code predictable/brute-forceable
            // by an attacker who can approximate the request time.
            var rng = new Random(DateTime.UtcNow.Millisecond);
            var token = rng.Next(100000, 999999).ToString();

            // In a real deployment this would be emailed to the user; it is
            // returned directly here for demonstration purposes.
            return Content($"A password reset code has been generated for '{username}': {token}");
        }
    }
}
