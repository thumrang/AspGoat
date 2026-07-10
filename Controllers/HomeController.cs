using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AspGoat.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using AspGoat.Data;
using System.Data.SqlClient;
using Microsoft.Data.Sqlite;
using System.Xml;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Formatting = Newtonsoft.Json.Formatting;
using System.Text.Json;
using System.Threading.Tasks;
using RazorLight;

namespace AspGoat.Controllers;

[Authorize]
public class HomeController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _config;

    // Vulnerable: hardcoded cloud credentials committed to source control.
    // Trivially detected by secret-scanning tools (gitleaks, trufflehog, etc.)
    private const string AwsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
    private const string AwsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY0EXAMPLEKEY";

    public HomeController(ApplicationDbContext context, IConfiguration config)
    {
        _context = context;
        _config = config;
    }

    public IActionResult Dashboard()
    {
        return View();
    }

    [HttpGet]
    public IActionResult ReflectedXSS(string query)
    {
        ViewData["Query"] = query;
        return View();
    }

    [HttpGet]
    public IActionResult StoredXSS()
    {
        var comments = _context.Comments.Select(c => c.Content).ToList();
        return View(comments);
    }

    [HttpPost]
    public IActionResult StoredXSS(string comment)
    {
        
        var newComment = new Comment
        {
            Content = comment
        };

        _context.Comments.Add(newComment);
        _context.SaveChanges();

        return RedirectToAction("StoredXSS");
    }

    [HttpGet]
    public IActionResult SqlInjection()
    {
        string ip = Request.Headers["X-Forwarded-For"].ToString();

        if (String.IsNullOrEmpty(ip)) ip = "127.0.0.1";

        var _connString = _config.GetConnectionString("DefaultConnection");

        using var conn = new SqliteConnection(_connString);
        conn.Open();

        // Vulnerable to SQL Injection
        string query = "SELECT * FROM Users " + "WHERE LastLoginIP = '" + ip + "'";

        using var cmd = new SqliteCommand(query, conn);
        using var reader = cmd.ExecuteReader();

        if (reader.Read()) // take first row only
        {
            ViewData["Id"] = reader["Id"].ToString();
            ViewData["UserName"] = reader["UserName"].ToString();
            ViewData["PasswordHash"] = reader["PasswordHash"].ToString();
            ViewData["Email"] = reader["Email"].ToString();
            ViewData["LastLoginIP"] = reader["LastLoginIP"].ToString();
            ViewData["Role"] = reader["Role"].ToString();
        }

        return View();
    }

    [HttpGet]
    public IActionResult BrokenAuthentication()
    {
        return View();
    }

    [HttpPost]
    public IActionResult BrokenAuthentication(string username, string password)
    {
        if (username != "admin")
        {
            //Username enumeration vulnerability
            ViewData["Error"] = "User does not exist.";
            return View();
        }

        if (password != "admin")
        {
            //Indicates username is valid
            ViewData["Error"] = "Incorrect password.";
            return View();
        }

        ViewData["LoginMessage"] = $"Welcome, {username}!";
        return View();
    }

    [HttpGet]
    public IActionResult InformationDisclosure()
    {
        return View();
    }

    [HttpGet]
    public IActionResult XXE()
    {
        return View();
    }

    [HttpPost]
    public IActionResult XXE(string xmlInput)
    {
        string result = "";
        try
        {
            var xmlDoc = new XmlDocument
            {
                XmlResolver = new XmlUrlResolver()  //Enables external entity fetching
            };
            //Vulnerable: External entity resolution enabled by default
            xmlDoc.LoadXml(xmlInput);
            result = xmlDoc.InnerText;
        }
        catch (Exception ex)
        {
            result = $"Error: {ex.Message}";
        }

        ViewData["ParsedXml"] = result;
        return View();
    }

    [HttpGet]
    public IActionResult OpenRedirect(string returnUrl)
    {
        if (returnUrl != null)
        {
            return Redirect(returnUrl);
        }

        return View();
    }

    [HttpGet]
    public IActionResult InsecureDirectObjectReference()
    {
        return View(new Dictionary<string, object>());
    }

    [HttpPost]
    public IActionResult InsecureDirectObjectReference(int UserId)
    {
        // Simulating dynamic user data with hardcoding
        var userData = new Dictionary<int, Dictionary<string, object>>
        {
            { 1, new Dictionary<string, object>
                {
                    { "user_id", 1 },
                    { "username", "admin" },
                    { "email", "administrator@aspgoat.net" },
                    { "api_key", "a1b2c3d4e5f678g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8" },
                    { "account_status", "active" }
                }
            },
            { 2, new Dictionary<string, object>
                {
                    { "user_id", 2 },
                    { "username", "john356" },
                    { "email", "john.smith@user.net" },
                    { "api_key", "a1b2c3d4e5f678g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8" },
                    { "account_status", "active" }
                }
            }
        };

        if (userData.ContainsKey(UserId))
        {
            return View(userData[UserId]);
        }

        return NotFound("User not found");
    }

    [HttpGet]
    public IActionResult DomXSS()
    {
        return View();
    }

    [HttpGet]
    public IActionResult PrototypePollution()
    {
        return View();
    }

    [HttpGet]
    public IActionResult LFI()
    {
        return View();
    }

    [HttpGet]
    public IActionResult Download(string file)
    {
        // Vulnerable file concatination 
        var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", file);

        if (!System.IO.File.Exists(path))
        {
            return NotFound("File not found");
        }

        var contentType = "application/octet-stream";
        var fileBytes = System.IO.File.ReadAllBytes(path);

        return File(fileBytes, contentType, file);
    }

    [HttpGet]
    public IActionResult FileUpload()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> FileUpload(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return Content("No file selected.");

        var uploads = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads");
        Directory.CreateDirectory(uploads);

        // Vulnerable filename concatenation
        var filePath = Path.Combine(uploads, file.FileName);
        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            await file.CopyToAsync(stream);
        }

        return Content($"File {file.FileName} uploaded successfully to /uploads.");
    }

    [HttpGet]
    public IActionResult CommandInjection(string domain)
    {
        if (!String.IsNullOrEmpty(domain))
        {
            // Choose shell on the basis of OS
            string shell, args;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                shell = "cmd.exe";
                // VULNERABLE: direct concatenation of user input into shell command
                args = $"/c nslookup {domain}";
            }
            else
            {
                shell = "/bin/bash";
                // VULNERABLE: direct concatenation of user input into shell command    
                args = $"-c \"nslookup {domain}\"";
            }

            var process = new Process();
            process.StartInfo.FileName = shell;
            process.StartInfo.Arguments = args;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            ViewData["Output"] = output;
        }

        return View();
    }

    [HttpGet]
    public IActionResult InsecureDeserialization()
    {
        return View();
    }

    [HttpPost]
    public IActionResult InsecureDeserialization([FromBody] JsonElement body)
    {
        var json = body.GetRawText();

        var settings = new JsonSerializerSettings
        {
            TypeNameHandling = TypeNameHandling.None,
            MetadataPropertyHandling = MetadataPropertyHandling.Ignore
        };

        var obj = JsonConvert.DeserializeObject<SafeMessage>(json, settings);

        var message = obj?.Message;

        return Json(new { message });
    }

    [HttpGet]
    public async Task<IActionResult> CSRF()
    {
        var email = await _context.EmailIds.Select(e => e.Email).FirstOrDefaultAsync();
        ViewData["Email"] = email;
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> CSRF(int id, string email) 
    {
        var emailRow = await _context.EmailIds.FindAsync(id);
        if (emailRow == null)
            return NotFound($"EmailId {id} not found.");

        emailRow.Email = email;
        await _context.SaveChangesAsync();

        return RedirectToAction();
    }

    [HttpGet]
    public IActionResult SSRF()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> SSRF(string targetUrl)
    {
        // Vulnerable as the targetUrl is not whitelisted
        using var http = new HttpClient();

        var response = await http.GetStringAsync(targetUrl);
        ViewData["Response"] = response;

        return View();
    }

    [HttpGet]
    // Vulnerable as the X-Forwarded-Host is not taken into account for the Cache Key
    [ResponseCache(Duration = 60, Location = ResponseCacheLocation.Any, VaryByHeader = "")]
    public IActionResult CachePoisoning()
    {
        var host = Request.Headers["X-Forwarded-Host"];

        ViewData["X-Forwarded-Host"] = host;

        return View();
    }

    [HttpGet]
    public async Task<IActionResult> SSTI([FromServices] IRazorLightEngine razor)
    {
        var userName = _context.Users.Where(u => u.Id == 2).Select(u => u.UserName).FirstOrDefault();

        var key = Guid.NewGuid().ToString("N");

        var html = "";

        try
        {
            // Vulnerable as it compiles & executes user-supplied Razor (Razorlight Template Engine)
            html = await razor.CompileRenderStringAsync(key, userName ?? "Null", new { });
        }
        catch (Exception e)
        {
            html = e.Message;
        }

        ViewData["Html"] = html;

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> SSTI(int id, string userName)
    {
        var userRow = await _context.Users.FindAsync(id);
        if (userRow == null)
            return NotFound($"User {id} not found.");

        userRow.UserName = userName;
        await _context.SaveChangesAsync();

        return RedirectToAction();
    }

    [AllowAnonymous]
    [HttpGet("/internal/config")]
    public IActionResult InternalConfig()
    {
        return Ok(new
        {
            service = "AspGoat.Internal.Config",
            dbConnection = "Server=aspgoat-db;User=app;Password=SuperSecret!",
            jwtSigningKey = "FAKE-KEY-123456789",
            adminEmail = "admin@aspgoat.local"
        });
    }

    public IActionResult LLM_Vulnerabilities()
    {
        return View("LLM_Vuln");
    }

    [HttpGet]
    public IActionResult CloudSync()
    {
        // Vulnerable: hardcoded, plaintext cloud credentials are used directly
        // to "authenticate" to a storage backend and are echoed back here,
        // making the exposure easy to confirm via source review or a simple
        // request/response inspection.
        var backupConfig = new
        {
            accessKeyId = AwsAccessKeyId,
            secretAccessKey = AwsSecretAccessKey,
            bucket = "aspgoat-backups",
            region = "us-east-1"
        };

        return Json(new { status = "synced", credentials = backupConfig });
    }

    [HttpGet]
    public IActionResult ViewLog(string file)
    {
        var logsDir = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "logs");

        // Vulnerable: user-controlled filename is concatenated into a path
        // with no sanitization, canonicalization check, or containment
        // validation, allowing "../" traversal to read arbitrary files
        // outside of the intended logs directory.
        var path = Path.Combine(logsDir, file);

        if (!System.IO.File.Exists(path))
        {
            return NotFound("Log not found");
        }

        var content = System.IO.File.ReadAllText(path);
        return Content(content, "text/plain");
    }

    [HttpGet]
    public async Task<IActionResult> SetNickname(int id = 2)
    {
        var user = await _context.Users.FindAsync(id);
        return Content($"User {id} nickname: {user?.Nickname ?? "(none set)"}");
    }

    [HttpPost]
    public async Task<IActionResult> SetNickname(int id, string nickname)
    {
        var user = await _context.Users.FindAsync(id);
        if (user == null)
            return NotFound($"User {id} not found.");

        // Safe here: EF Core parameterizes this write, so it looks clean
        // in isolation. The injectable sink is downstream — see
        // SearchActivity below, which is why this is a second-order
        // (stored) SQL injection rather than a simple reflected one.
        user.Nickname = nickname;
        await _context.SaveChangesAsync();

        return RedirectToAction();
    }

    [HttpGet]
    public IActionResult SearchActivity(int userId)
    {
        var nickname = _context.Users
            .Where(u => u.Id == userId)
            .Select(u => u.Nickname)
            .FirstOrDefault() ?? "";

        var _connString = _config.GetConnectionString("DefaultConnection");
        using var conn = new SqliteConnection(_connString);
        conn.Open();

        // Vulnerable: second-order SQL injection. `nickname` originated
        // from user input that was safely parameterized when written in
        // SetNickname, but once read back out of the database it is
        // concatenated directly into a new query string here.
        string query = "SELECT * FROM Comments WHERE Content LIKE '%" + nickname + "%'";

        using var cmd = new SqliteCommand(query, conn);
        using var reader = cmd.ExecuteReader();

        var results = new List<string>();
        while (reader.Read())
        {
            results.Add(reader["Content"].ToString() ?? "");
        }

        return Json(results);
    }

    [HttpPost]
    public IActionResult DeleteComment(int id, bool isAdmin)
    {
        // Vulnerable: broken access control. The authorization decision
        // trusts a client-supplied form field (`isAdmin`) instead of the
        // authenticated user's server-side role claim (e.g.
        // User.IsInRole("Admin")), so any authenticated user can delete
        // any comment simply by setting isAdmin=true in the POST body.
        if (!isAdmin)
        {
            return Forbid();
        }

        var comment = _context.Comments.Find(id);
        if (comment == null)
            return NotFound();

        _context.Comments.Remove(comment);
        _context.SaveChanges();

        return RedirectToAction("StoredXSS");
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
