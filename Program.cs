using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";
        options.Cookie.Name = "mlb.auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(12);
        options.SlidingExpiration = true;
    })
    .AddGoogle(options =>
    {
        options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? "";
        options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? "";
        options.CallbackPath = "/signin-google";

        options.Events.OnRedirectToAuthorizationEndpoint = context =>
        {
            context.Response.Redirect(context.RedirectUri.Replace("http://", "https://"));
            return Task.CompletedTask;
        };

        options.Events.OnTicketReceived = async context =>
        {
            var email = context.Principal?.FindFirstValue(ClaimTypes.Email);
            if (!string.IsNullOrEmpty(email))
            {
                var userStore = context.HttpContext.RequestServices.GetRequiredService<UserStore>();
                var user = userStore.GetByEmail(email);
                if (user == null)
                {
                    // Auto-register new Google users
                    user = new PortalUser 
                    { 
                        Username = email.Split('@')[0], 
                        Email = email, 
                        Role = "User", 
                        IsOnboarded = false 
                    };
                    userStore.AddUser(user);
                }

                var claims = new List<Claim>
                {
                    new(ClaimTypes.Name, user.Username),
                    new(ClaimTypes.Role, user.Role),
                    new("IsOnboarded", user.IsOnboarded.ToString())
                };
                var appIdentity = new ClaimsIdentity(claims);
                context.Principal?.AddIdentity(appIdentity);
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("OwnerOnly", policy => policy.RequireRole("Owner"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User", "Owner"));
});

builder.Services.AddSingleton<RequestAnalyticsStore>();
builder.Services.AddSingleton<ProjectStore>();
builder.Services.AddSingleton<UserStore>(sp => {
    var config = sp.GetRequiredService<IConfiguration>();
    var initialUsers = config.GetSection("AdminPortal:Users").Get<List<PortalUser>>() ?? [];
    return new UserStore(initialUsers);
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();
var startTime = DateTimeOffset.UtcNow;

var users = builder.Configuration.GetSection("AdminPortal:Users")
    .Get<List<PortalUser>>() ?? [];

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    var analytics = context.RequestServices.GetRequiredService<RequestAnalyticsStore>();
    var path = context.Request.Path.Value ?? "/";
    var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

    analytics.TrackRequest(path, ip);

    try
    {
        await next();
    }
    catch (Exception ex)
    {
        analytics.TrackException(path, ex.Message);
        throw;
    }
    finally
    {
        stopwatch.Stop();
        analytics.TrackResponse(path, context.Response.StatusCode, stopwatch.ElapsedMilliseconds);
    }
});

// --- Public API ---
app.MapPost("/api/contact", async (HttpContext context, ProjectStore projects) =>
{
    var form = await context.Request.ReadFormAsync();
    var name = form["name"].ToString();
    var email = form["email"].ToString();
    var phone = form["phone"].ToString();
    var type = form["type"].ToString(); // "Quote", "Consultation", "Emergency"
    var message = form["message"].ToString();

    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(phone))
    {
        return Results.BadRequest("Name and Phone are required.");
    }

    projects.AddRequest(new ProjectRequest(
        Guid.NewGuid().ToString("N")[..8],
        name,
        email,
        phone,
        type,
        message,
        DateTimeOffset.UtcNow
    ));

    return Results.Ok(new { message = "Request submitted successfully. Benny will contact you soon." });
});

// --- Owner API ---
app.MapGet("/api/owner/projects", [Authorize(Policy = "OwnerOnly")] (ProjectStore projects) => 
    Results.Json(projects.GetAll()));

app.MapPost("/api/owner/projects", [Authorize(Policy = "OwnerOnly")] (HttpContext context, ProjectStore projects) =>
{
    var id = Guid.NewGuid().ToString("N")[..8];
    var name = context.Request.Query["name"].ToString();
    var email = context.Request.Query["email"].ToString();
    var phone = context.Request.Query["phone"].ToString();
    var type = context.Request.Query["type"].ToString();
    var date = context.Request.Query["date"].ToString();
    var priceRange = context.Request.Query["priceRange"].ToString();
    
    DateTimeOffset? scheduledDate = null;
    if (DateTimeOffset.TryParse(date, out var d)) scheduledDate = d;

    projects.AddRequest(new ProjectRequest(id, name, email, phone, type, "Manual entry", DateTimeOffset.UtcNow) 
    { 
        Status = scheduledDate.HasValue ? "Scheduled" : "Approved",
        ScheduledDate = scheduledDate,
        PriceRange = priceRange
    });
    return Results.Ok();
});

app.MapPut("/api/owner/projects/{id}", [Authorize(Policy = "OwnerOnly")] (string id, HttpContext context, ProjectStore projects) =>
{
    var name = context.Request.Query["name"].ToString();
    var email = context.Request.Query["email"].ToString();
    var phone = context.Request.Query["phone"].ToString();
    var type = context.Request.Query["type"].ToString();
    var date = context.Request.Query["date"].ToString();
    var status = context.Request.Query["status"].ToString();
    var notes = context.Request.Query["notes"].ToString();
    var assignedTo = context.Request.Query["assignedTo"].ToString();
    var priceRange = context.Request.Query["priceRange"].ToString();

    DateTimeOffset? scheduledDate = null;
    if (DateTimeOffset.TryParse(date, out var d)) scheduledDate = d;

    if (projects.UpdateJob(id, name, email, phone, type, status, scheduledDate, notes, assignedTo, priceRange))
        return Results.Ok();
    
    return Results.NotFound();
});

// --- Announcement API ---
app.MapGet("/api/announcement", () => Results.Json(new { message = AnnouncementStore.Message }));
app.MapPost("/api/owner/announcement", [Authorize(Policy = "OwnerOnly")] (HttpContext context) => {
    AnnouncementStore.Message = context.Request.Query["m"].ToString();
    return Results.Ok();
});

// --- User Feed API ---
app.MapGet("/api/user/my-projects", [Authorize(Policy = "UserOnly")] (HttpContext context, ProjectStore projects) =>
{
    var username = context.User.Identity?.Name ?? "";
    var myJobs = projects.GetAll().Where(p => p.AssignedTo.Equals(username, StringComparison.OrdinalIgnoreCase) || p.AssignedTo == "All");
    return Results.Json(myJobs);
});

app.MapDelete("/api/owner/projects/{id}", [Authorize(Policy = "OwnerOnly")] (string id, ProjectStore projects) =>
{
    if (projects.DeleteJob(id))
        return Results.Ok();
    
    return Results.NotFound();
});

app.MapPost("/api/owner/projects/{id}/status", [Authorize(Policy = "OwnerOnly")] (string id, HttpContext context, ProjectStore projects) =>
{
    var status = context.Request.Query["status"].ToString();
    var dateStr = context.Request.Query["date"].ToString();
    
    DateTimeOffset? scheduledDate = null;
    if (DateTimeOffset.TryParse(dateStr, out var d)) scheduledDate = d;

    if (projects.UpdateStatus(id, status, scheduledDate))
        return Results.Ok();
    
    return Results.NotFound();
});

app.MapGet("/login-google", () => 
    Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }, [GoogleDefaults.AuthenticationScheme]));

app.MapGet("/onboarding", [Authorize] (HttpContext context, UserStore userStore) =>
{
    var username = context.User.Identity?.Name ?? "";
    var user = userStore.Get(username);
    if (user == null || user.IsOnboarded) return Results.Redirect("/");

    var html = HtmlTemplates.OnboardingPageHtml
        .Replace("{{USERNAME}}", user.Username)
        .Replace("{{EMAIL}}", user.Email);
    return Results.Content(html, "text/html");
});

app.MapPost("/api/user/complete-onboarding", [Authorize] async (HttpContext context, UserStore userStore, ProjectStore projects) =>
{
    var username = context.User.Identity?.Name ?? "";
    var user = userStore.Get(username);
    if (user == null) return Results.NotFound();

    var email = context.Request.Query["email"].ToString();
    var phone = context.Request.Query["phone"].ToString();
    var questions = context.Request.Query["questions"].ToString();

    user.Email = email;
    user.Phone = phone;
    user.IsOnboarded = true;
    userStore.AddUser(user);

    if (!string.IsNullOrWhiteSpace(questions))
    {
        projects.AddRequest(new ProjectRequest(Guid.NewGuid().ToString("N")[..8], user.Username, email, phone, "Onboarding Inquiry", questions, DateTimeOffset.UtcNow));
    }

    // Refresh cookie with updated onboarding status
    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, user.Username),
        new(ClaimTypes.Role, user.Role),
        new("IsOnboarded", "True")
    };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

    return Results.Ok();
});

app.MapGet("/login", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        if (context.User.FindFirstValue("IsOnboarded") != "True" && !context.User.IsInRole("Owner")) 
            return Results.Redirect("/onboarding");
        return Results.Redirect(context.User.IsInRole("Owner") ? "/owner/dashboard" : "/user/dashboard");
    }

    return Results.Content(HtmlTemplates.LoginPageHtml.Replace("{{ERROR}}", ""), "text/html");
});

app.MapPost("/login", async (HttpContext context, UserStore userStore, RequestAnalyticsStore analytics) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = (form["username"].ToString() ?? string.Empty).Trim();
    var password = form["password"].ToString() ?? string.Empty;

    var matchedUser = userStore.Get(username);
    
    if (matchedUser is null)
    {
        Console.WriteLine($"[Login] Failed attempt for unknown user: {username}");
        return Results.Content(HtmlTemplates.LoginPageHtml.Replace("{{ERROR}}", "Invalid username or password."), "text/html");
    }

    if (!string.Equals(matchedUser.Password, password, StringComparison.Ordinal))
    {
        Console.WriteLine($"[Login] Failed attempt for user: {username} (Incorrect password)");
        return Results.Content(HtmlTemplates.LoginPageHtml.Replace("{{ERROR}}", "Invalid username or password."), "text/html");
    }

    Console.WriteLine($"[Login] Successful login for: {username} ({matchedUser.Role})");

    var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    analytics.TrackLogin(username, ip);

    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, matchedUser.Username),
        new(ClaimTypes.Role, matchedUser.Role),
        new("IsOnboarded", matchedUser.IsOnboarded.ToString())
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    if (!matchedUser.IsOnboarded && matchedUser.Role != "Owner") return Results.Redirect("/onboarding");

    return Results.Redirect(matchedUser.Role.Equals("Owner", StringComparison.OrdinalIgnoreCase)
        ? "/owner/dashboard"
        : "/user/dashboard");
});

app.MapPost("/api/register", async (HttpContext context, UserStore userStore) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = (form["username"].ToString() ?? string.Empty).Trim();
    var password = form["password"].ToString() ?? string.Empty;

    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        return Results.BadRequest("Username and Password are required.");

    if (userStore.Get(username) != null)
        return Results.BadRequest("Username already exists.");

    userStore.AddUser(new PortalUser { Username = username, Password = password, Role = "User" });
    return Results.Ok(new { message = "Registration successful. Please login." });
});

app.MapPost("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
});

app.MapGet("/owner/dashboard", [Authorize(Policy = "OwnerOnly")] () =>
    Results.Content(HtmlTemplates.OwnerDashboardHtml, "text/html"));

app.MapGet("/user/dashboard", [Authorize(Policy = "UserOnly")] () =>
    Results.Content(HtmlTemplates.UserDashboardHtml, "text/html"));

// --- User Management API ---
app.MapGet("/api/owner/users", [Authorize(Policy = "OwnerOnly")] (UserStore userStore) => 
    Results.Json(userStore.GetAll()));

app.MapPost("/api/owner/users", [Authorize(Policy = "OwnerOnly")] (HttpContext context, UserStore userStore) =>
{
    var username = context.Request.Query["username"].ToString();
    var password = context.Request.Query["password"].ToString();
    var role = context.Request.Query["role"].ToString();
    
    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        return Results.BadRequest("Username and Password are required.");

    userStore.AddUser(new PortalUser { Username = username, Password = password, Role = role });
    return Results.Ok();
});

app.MapDelete("/api/owner/users/{username}", [Authorize(Policy = "OwnerOnly")] (string username, UserStore userStore) =>
{
    userStore.RemoveUser(username);
    return Results.Ok();
});

app.MapGet("/api/owner/analytics", [Authorize(Policy = "OwnerOnly")] (RequestAnalyticsStore analytics) =>
{
    var snapshot = analytics.GetSnapshot();
    var noise = new[] { "/favicon.ico", "/api/owner/analytics", "/api/user/diagnostics", "/.well-known" };
    
    return Results.Json(new
    {
        uptimeSeconds = (int)(DateTimeOffset.UtcNow - startTime).TotalSeconds,
        snapshot.TotalRequests,
        snapshot.TotalLogins,
        snapshot.UniqueVisitors,
        snapshot.Status2xx,
        snapshot.Status4xx,
        snapshot.Status5xx,
        topRoutes = snapshot.RouteHits
            .Where(x => !noise.Any(n => x.Key.StartsWith(n, StringComparison.OrdinalIgnoreCase)) 
                     && !x.Key.EndsWith(".js") && !x.Key.EndsWith(".css") && !x.Key.EndsWith(".png"))
            .OrderByDescending(x => x.Value)
            .Take(10)
            .Select(x => new { route = x.Key == "/" ? "Home (index.html)" : x.Key, hits = x.Value }),
        recentErrors = snapshot.RecentErrors.Take(10),
        loginHistory = snapshot.RecentLogins.Take(15)
    });
});

app.MapGet("/api/user/diagnostics", [Authorize(Policy = "UserOnly")] (HttpContext context, RequestAnalyticsStore analytics) =>
{
    var snapshot = analytics.GetSnapshot();
    return Results.Json(new
    {
        environment = app.Environment.EnvironmentName,
        machine = Environment.MachineName,
        os = Environment.OSVersion.ToString(),
        dotnet = Environment.Version.ToString(),
        requestPath = context.Request.Path.Value,
        requestId = context.TraceIdentifier,
        totalRequests = snapshot.TotalRequests,
        recentSlowRoutes = snapshot.RouteDurations
            .Where(x => !x.Key.EndsWith(".js") && !x.Key.EndsWith(".css"))
            .OrderByDescending(x => x.Value)
            .Take(8)
            .Select(x => new { route = x.Key, avgMs = Math.Round(x.Value, 1) }),
        recentStatuses = snapshot.RecentStatuses.Take(15)
    });
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.Run();

public sealed class PortalUser
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Role { get; set; } = "";
    public string Email { get; set; } = "";
    public string Phone { get; set; } = "";
    public bool IsOnboarded { get; set; } = false;
}

internal static class AnnouncementStore
{
    private static readonly string _path = Path.Combine(AppContext.BaseDirectory, "announcement.txt");
    private static string _message = File.Exists(_path) ? File.ReadAllText(_path) : "Welcome to the MLB Portal!";

    public static string Message
    {
        get => _message;
        set { _message = value; try { File.WriteAllText(_path, value); } catch { } }
    }
}

internal sealed class UserStore
{
    private readonly ConcurrentDictionary<string, PortalUser> _users = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _filePath = Path.Combine(AppContext.BaseDirectory, "users.json");

    public UserStore(IEnumerable<PortalUser> initialUsers)
    {
        // 1. Load from persistent storage first
        if (File.Exists(_filePath))
        {
            try 
            { 
                var saved = System.Text.Json.JsonSerializer.Deserialize<List<PortalUser>>(File.ReadAllText(_filePath));
                if (saved != null) foreach (var u in saved) _users.TryAdd(u.Username, u);
            } catch { /* ignore */ }
        }
        
        // 2. Apply/Override with initial users from appsettings.json
        // This ensures that if the user updates appsettings.json, those credentials take precedence.
        foreach (var user in initialUsers)
        {
            _users.AddOrUpdate(user.Username, user, (_, _) => user);
        }
        Save();
    }

    private void Save() => File.WriteAllText(_filePath, System.Text.Json.JsonSerializer.Serialize(_users.Values));

    public void AddUser(PortalUser user) { _users.AddOrUpdate(user.Username, user, (_, _) => user); Save(); }
    public void RemoveUser(string username) { _users.TryRemove(username, out _); Save(); }
    public IEnumerable<PortalUser> GetAll() => _users.Values;
    public PortalUser? Get(string username) => _users.TryGetValue(username, out var u) ? u : null;
    public PortalUser? GetByEmail(string email) => _users.Values.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
}

internal sealed class ProjectStore
{
    private readonly ConcurrentDictionary<string, ProjectRequest> _projects = new();
    private readonly string _filePath = Path.Combine(AppContext.BaseDirectory, "projects.json");

    public ProjectStore()
    {
        if (File.Exists(_filePath))
        {
            try 
            { 
                var saved = System.Text.Json.JsonSerializer.Deserialize<List<ProjectRequest>>(File.ReadAllText(_filePath));
                if (saved != null) foreach (var p in saved) _projects.TryAdd(p.Id, p);
            } catch { /* ignore */ }
        }

        if (_projects.IsEmpty)
        {
            AddRequest(new ProjectRequest("m-001", "John Doe", "john@example.com", "0215551234", "Solar Quote", "Needs 5kW system for home in Strand", DateTimeOffset.UtcNow.AddHours(-5)) { Status = "Pending" });
            AddRequest(new ProjectRequest("m-002", "Sarah Smith", "sarah@somerset.co.za", "0829994433", "Emergency", "Main DB tripping repeatedly", DateTimeOffset.UtcNow.AddDays(-1)) { Status = "Approved" });
        }
    }

    private void Save() => File.WriteAllText(_filePath, System.Text.Json.JsonSerializer.Serialize(_projects.Values));

    public void AddRequest(ProjectRequest request) { _projects.TryAdd(request.Id, request); Save(); }
    
    public IEnumerable<ProjectRequest> GetAll() => _projects.Values.OrderByDescending(x => x.CreatedAt);

    public bool UpdateJob(string id, string name, string email, string phone, string type, string status, DateTimeOffset? date, string notes = "", string assignedTo = "", string priceRange = "")
    {
        if (_projects.TryGetValue(id, out var p))
        {
            var updated = new ProjectRequest(id, name, email, phone, type, p.Message, p.CreatedAt)
            {
                Status = status,
                ScheduledDate = date,
                Notes = notes,
                AssignedTo = assignedTo,
                PriceRange = priceRange
            };
            var success = _projects.TryUpdate(id, updated, p);
            if (success) Save();
            return success;
        }
        return false;
    }

    public bool DeleteJob(string id) { var s = _projects.TryRemove(id, out _); if(s) Save(); return s; }

    public bool UpdateStatus(string id, string status, DateTimeOffset? date = null)
    {
        if (_projects.TryGetValue(id, out var p))
        {
            p.Status = status;
            if (date.HasValue) p.ScheduledDate = date;
            Save();
            return true;
        }
        return false;
    }
}

internal sealed class ProjectRequest
{
    public string Id { get; init; }
    public string Name { get; init; }
    public string Email { get; init; }
    public string Phone { get; init; }
    public string Type { get; init; }
    public string Message { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public string Status { get; set; } = "Pending"; // Pending, Approved, Scheduled, Completed, Declined
    public DateTimeOffset? ScheduledDate { get; set; }
    public string Notes { get; set; } = "";
    public string AssignedTo { get; set; } = "All";
    public string PriceRange { get; set; } = "";

    public ProjectRequest(string id, string name, string email, string phone, string type, string message, DateTimeOffset createdAt)
    {
        Id = id; Name = name; Email = email; Phone = phone; Type = type; Message = message; CreatedAt = createdAt;
    }
}

internal sealed class RequestAnalyticsStore
{
    private readonly ConcurrentDictionary<string, int> _routeHits = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _visitorHits = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (double totalMs, int count)> _routeDuration = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<string> _recentErrors = new();
    private readonly ConcurrentQueue<string> _recentStatuses = new();
    private readonly ConcurrentQueue<string> _recentLogins = new();
    private readonly string _filePath = Path.Combine(AppContext.BaseDirectory, "analytics_state.json");

    private int _totalRequests;
    private int _totalLogins;
    private int _status2xx;
    private int _status4xx;
    private int _status5xx;

    public RequestAnalyticsStore()
    {
        if (File.Exists(_filePath))
        {
            try
            {
                var saved = System.Text.Json.JsonSerializer.Deserialize<AnalyticsData>(File.ReadAllText(_filePath));
                if (saved != null)
                {
                    _totalRequests = saved.TotalRequests;
                    _totalLogins = saved.TotalLogins;
                    _status2xx = saved.Status2xx;
                    _status4xx = saved.Status4xx;
                    _status5xx = saved.Status5xx;
                    foreach (var h in saved.RouteHits) _routeHits.TryAdd(h.Key, h.Value);
                    foreach (var h in saved.VisitorHits) _visitorHits.TryAdd(h.Key, h.Value);
                }
            } catch { }
        }
    }

    private void Save()
    {
        var data = new AnalyticsData(
            _totalRequests, _totalLogins, _status2xx, _status4xx, _status5xx,
            new Dictionary<string, int>(_routeHits),
            new Dictionary<string, int>(_visitorHits));
        File.WriteAllText(_filePath, System.Text.Json.JsonSerializer.Serialize(data));
    }

    public void TrackRequest(string path, string ip)
    {
        _routeHits.AddOrUpdate(path, 1, (_, value) => value + 1);
        _visitorHits.AddOrUpdate(ip, 1, (_, value) => value + 1);
        Interlocked.Increment(ref _totalRequests);
        if (_totalRequests % 10 == 0) Save();
    }

    public void TrackLogin(string username, string ip) 
    { 
        Interlocked.Increment(ref _totalLogins); 
        EnqueueBounded(_recentLogins, $"{DateTimeOffset.UtcNow:HH:mm} | {username} | {ip}");
        Save(); 
    }

    public void TrackResponse(string path, int statusCode, long elapsedMs)
    {
        if (statusCode is >= 200 and < 300) Interlocked.Increment(ref _status2xx);
        else if (statusCode is >= 400 and < 500) Interlocked.Increment(ref _status4xx);
        else if (statusCode >= 500) Interlocked.Increment(ref _status5xx);

        _routeDuration.AddOrUpdate(path, (elapsedMs, 1), (_, current) => (current.totalMs + elapsedMs, current.count + 1));
        EnqueueBounded(_recentStatuses, $"{DateTimeOffset.UtcNow:HH:mm:ss} | {statusCode} | {path}");
    }

    public void TrackException(string path, string message) => EnqueueBounded(_recentErrors, $"{DateTimeOffset.UtcNow:HH:mm:ss} | {path} | {message}");

    public AnalyticsSnapshot GetSnapshot()
    {
        return new AnalyticsSnapshot(
            Interlocked.CompareExchange(ref _totalRequests, 0, 0),
            Interlocked.CompareExchange(ref _totalLogins, 0, 0),
            _visitorHits.Count,
            Interlocked.CompareExchange(ref _status2xx, 0, 0),
            Interlocked.CompareExchange(ref _status4xx, 0, 0),
            Interlocked.CompareExchange(ref _status5xx, 0, 0),
            new Dictionary<string, int>(_routeHits),
            _routeDuration.ToDictionary(x => x.Key, x => x.Value.count == 0 ? 0 : x.Value.totalMs / x.Value.count),
            _recentErrors.Reverse().ToList(),
            _recentStatuses.Reverse().ToList(),
            _recentLogins.Reverse().ToList());
    }

    private static void EnqueueBounded(ConcurrentQueue<string> queue, string value)
    {
        queue.Enqueue(value);
        while (queue.Count > 40) queue.TryDequeue(out _);
    }

    private sealed record AnalyticsData(int TotalRequests, int TotalLogins, int Status2xx, int Status4xx, int Status5xx, Dictionary<string, int> RouteHits, Dictionary<string, int> VisitorHits);
}

internal sealed record AnalyticsSnapshot(
    int TotalRequests,
    int TotalLogins,
    int UniqueVisitors,
    int Status2xx,
    int Status4xx,
    int Status5xx,
    Dictionary<string, int> RouteHits,
    Dictionary<string, double> RouteDurations,
    List<string> RecentErrors,
    List<string> RecentStatuses,
    List<string> RecentLogins);

internal static class HtmlTemplates
{
public const string LoginPageHtml = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>MLB Portal Login</title>
  <style>
    body{font-family:Arial,sans-serif;background:#081326;color:#e8f0ff;display:grid;place-items:center;min-height:100vh;margin:0}
    .card{width:min(420px,92vw);background:#10203a;border:1px solid #284d82;border-radius:16px;padding:24px}
    h1{margin:0 0 8px;font-size:1.4rem}
    p{color:#b5c9e8}
    label{display:block;margin:12px 0 6px}
    input{width:100%;padding:10px;border-radius:10px;border:1px solid #355f99;background:#0c1a31;color:#fff;box-sizing:border-box}
    button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:10px;background:#0056b3;color:#fff;font-weight:700;cursor:pointer}
    button:hover{background:#004a99}
    .error{color:#ff9aa6;min-height:20px;font-size:0.9rem;margin-bottom:10px}
    .toggle-link{display:block;text-align:center;margin-top:20px;color:#3b82f6;text-decoration:none;font-size:0.9rem;cursor:pointer}
    .hidden{display:none}
  </style>
</head>
<body>
  <div class="card">
    <div id="login-section">
        <h1>Portal Login</h1>
        <p>Use your Owner or User credentials.</p>
        <div class="error">{{ERROR}}</div>
        <form method="post" action="/login">
            <label for="username">Username</label>
            <input id="username" name="username" required />
            <label for="password">Password</label>
            <input id="password" name="password" type="password" required />
            <button type="submit">Sign In</button>
        </form>
        
        <div style="margin-top:20px; display:flex; align-items:center; gap:10px; color:#56779e; font-size:0.85rem">
            <div style="flex:1; height:1px; background:#284d82"></div> OR <div style="flex:1; height:1px; background:#284d82"></div>
        </div>

        <button onclick="location.href='/login-google'" style="background:#fff; color:#1e293b; border:1px solid #d1d5db; margin-top:20px; display:flex; align-items:center; justify-content:center; gap:10px">
            <svg width="18" height="18" viewBox="0 0 18 18"><path d="M17.64 9.2c0-.63-.06-1.25-.16-1.84H9v3.49h4.84c-.21 1.12-.84 2.07-1.79 2.7l2.85 2.21c1.67-1.53 2.63-3.79 2.63-5.56z" fill="#4285F4"/><path d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.85-2.21c-.79.53-1.8.85-3.11.85-2.39 0-4.41-1.61-5.14-3.77L.95 13.04C2.42 16.03 5.46 18 9 18z" fill="#34A853"/><path d="M3.86 10.74c-.18-.54-.28-1.12-.28-1.74s.1-1.2.28-1.74L.95 4.96C.35 6.17 0 7.55 0 9s.35 2.83.95 4.04l2.91-2.3z" fill="#FBBC05"/><path d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.59C13.46.86 11.42 0 9 0 5.46 0 2.42 1.97.95 4.96l2.91 2.3C4.59 5.19 6.61 3.58 9 3.58z" fill="#EA4335"/></svg>
            Sign in with Google
        </button>

        <a class="toggle-link" onclick="toggleMode()">Don't have an account? Register here</a>
    </div>

    <div id="register-section" class="hidden">
        <h1>New User Registration</h1>
        <p>Create a standard user account.</p>
        <div id="reg-error" class="error"></div>
        <div class="form-group">
            <label for="reg-username">Choose Username</label>
            <input id="reg-username" required />
            <label for="reg-password">Choose Password</label>
            <input id="reg-password" type="password" required />
            <button onclick="register()">Create Account</button>
        </div>
        <a class="toggle-link" onclick="toggleMode()">Already have an account? Login</a>
    </div>
  </div>

  <script>
    function toggleMode() {
        document.getElementById('login-section').classList.toggle('hidden');
        document.getElementById('register-section').classList.toggle('hidden');
    }

    async function register() {
        const u = document.getElementById('reg-username').value;
        const p = document.getElementById('reg-password').value;
        const err = document.getElementById('reg-error');
        
        if(!u || !p) return err.innerText = "Username and Password required";
        
        const formData = new FormData();
        formData.append('username', u);
        formData.append('password', p);

        const resp = await fetch('/api/register', { method: 'POST', body: formData });
        if(resp.ok) {
            alert("Registration successful! Please login.");
            location.reload();
        } else {
            const txt = await resp.text();
            err.innerText = txt || "Registration failed.";
        }
    }
  </script>
</body>
</html>
""";

public const string OnboardingPageHtml = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Welcome to MLB | Setup Your Profile</title>
  <style>
    body{font-family:'Inter',system-ui,sans-serif;background:#0f172a;color:#f8fafc;display:grid;place-items:center;min-height:100vh;margin:0}
    .card{width:min(500px,92vw);background:#1e293b;border:1px solid #334155;border-radius:20px;padding:40px;box-shadow:0 20px 50px rgba(0,0,0,0.5)}
    h1{margin:0 0 12px;font-size:1.8rem;color:#3b82f6}
    p{color:#94a3b8;line-height:1.6;margin-bottom:32px}
    .form-group{margin-bottom:24px}
    label{display:block;margin-bottom:8px;font-size:0.9rem;font-weight:600;color:#cbd5e1}
    input, textarea{width:100%;padding:12px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#fff;box-sizing:border-box;font-size:1rem}
    input:focus, textarea:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,0.1)}
    button{margin-top:16px;width:100%;padding:14px;border:0;border-radius:12px;background:#3b82f6;color:#fff;font-weight:700;cursor:pointer;font-size:1rem;transition:all 0.2s}
    button:hover{background:#2563eb;transform:translateY(-1px)}
    .error{color:#ef4444;font-size:0.9rem;margin-top:12px;text-align:center}
  </style>
</head>
<body>
  <div class="card">
    <h1>Welcome, {{USERNAME}}!</h1>
    <p>We're excited to have you on board. Please provide your contact details so we can manage your projects effectively.</p>
    
    <div id="onboarding-form">
        <div class="form-group">
            <label for="email">Work Email</label>
            <input type="email" id="email" value="{{EMAIL}}" placeholder="you@example.com" />
        </div>
        <div class="form-group">
            <label for="phone">Phone Number (WhatsApp preferred)</label>
            <input type="text" id="phone" placeholder="082 123 4567" />
        </div>
        <div class="form-group">
            <label for="questions">Any initial questions or requests?</label>
            <textarea id="questions" rows="3" placeholder="e.g. I need a solar quote for my office."></textarea>
        </div>
        <button onclick="completeOnboarding()">Finish Setup</button>
        <div id="error" class="error"></div>
    </div>
  </div>

  <script>
    async function completeOnboarding() {
        const email = document.getElementById('email').value;
        const phone = document.getElementById('phone').value;
        const questions = document.getElementById('questions').value;
        const err = document.getElementById('error');

        if(!email || !phone) return err.innerText = "Email and Phone are required.";

        const resp = await fetch(`/api/user/complete-onboarding?email=${encodeURIComponent(email)}&phone=${encodeURIComponent(phone)}&questions=${encodeURIComponent(questions)}`, { method: 'POST' });
        if(resp.ok) {
            window.location.href = '/';
        } else {
            const txt = await resp.text();
            err.innerText = txt || "Failed to save profile.";
        }
    }
  </script>
</body>
</html>
""";

public const string OwnerDashboardHtml = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Owner Management | MLB</title>
  <style>
    :root { --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f8fafc; --muted: #94a3b8; --primary: #3b82f6; --success: #22c55e; --danger: #ef4444; --warning: #f59e0b; }
    body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);margin:0;display:flex;min-height:100vh}
    
    /* Sidebar */
    aside { width: 240px; background: #020617; border-right: 1px solid var(--border); padding: 24px; display: flex; flex-direction: column; transition: transform 0.3s ease; z-index: 1000; }
    .nav-btn { padding: 12px 16px; border-radius: 8px; cursor: pointer; margin-bottom: 8px; font-weight: 500; color: var(--muted); transition: all 0.2s; display: flex; align-items: center; gap: 12px; }
    .nav-btn:hover { background: var(--card); color: var(--text); }
    .nav-btn.active { background: var(--primary); color: white; }
    
    /* Main Content */
    main { flex: 1; padding: 32px; overflow-y: auto; max-width: 100vw; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }
    .mobile-header { display: none; background: #020617; border-bottom: 1px solid var(--border); padding: 12px 20px; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 900; }
    .btn-action { padding: 8px 16px; border-radius: 8px; border: 1px solid var(--border); background: var(--card); color: var(--text); cursor: pointer; }
    .btn-primary { background: var(--primary); border: 0; color: white; font-weight: 600; }
    
    /* UI Components */
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 24px; margin-bottom: 32px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; }
    .section-title { font-size: 1.1rem; font-weight: 600; margin: 0 0 20px 0; display: flex; align-items: center; justify-content: space-between; }
    
    .announcement-bar { background: rgba(59,130,246,0.1); border: 1px solid var(--primary); color: var(--text); padding: 12px 20px; border-radius: 12px; margin-bottom: 32px; display: flex; align-items: center; justify-content: space-between; }

    /* Project Items */
    .project-item { background: #020617; border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; }
    .tag { font-size: 0.7rem; text-transform: uppercase; padding: 4px 8px; border-radius: 4px; font-weight: 700; }
    .tag.pending { background: rgba(245,158,11,0.1); color: var(--warning); }
    .tag.approved { background: rgba(34,197,94,0.1); color: var(--success); }
    .tag.scheduled { background: rgba(59,130,246,0.1); color: var(--primary); }
    .muted { color: var(--muted); }
    
    /* Calendar */
    .cal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .cal-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 4px; }
    .cal-day-label { text-align: center; font-size: 0.7rem; color: var(--muted); padding: 8px 0; }
    .cal-day { min-height: 80px; border: 1px solid var(--border); border-radius: 4px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; padding: 4px; font-size: 0.8rem; cursor: pointer; position: relative; transition: background 0.2s; }
    .cal-day:hover { background: #020617; }
    .cal-day.active { border-color: var(--primary); background: rgba(59,130,246,0.1); }
    .cal-day.has-job::after { content: ''; width: 4px; height: 4px; background: var(--primary); border-radius: 50%; position: absolute; bottom: 4px; }
    .cal-day.today { border-color: var(--primary); color: var(--primary); font-weight: 700; }
    .cal-day.drag-over { background: rgba(59,130,246,0.2); border-color: var(--primary); }
    .cal-job { font-size: 0.6rem; background: var(--primary); color: white; padding: 2px 4px; border-radius: 3px; margin-top: 2px; width: 95%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: center; cursor: grab; }
    .cal-job:active { cursor: grabbing; }

    /* Modal */
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 2000; }
    .modal { background: var(--bg); border: 1px solid var(--border); border-radius: 16px; width: min(500px, 90vw); padding: 32px; max-height: 90vh; overflow-y: auto; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; margin-bottom: 6px; font-size: 0.9rem; color: var(--muted); }
    .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 10px; background: #020617; border: 1px solid var(--border); border-radius: 8px; color: white; box-sizing: border-box; }

    .hidden { display: none; }

    /* Print Styles */
    @media print {
        aside, .mobile-header, .btn-action, .cal-header, header { display: none !important; }
        main { padding: 0 !important; }
        .card { border: 0 !important; }
        #agenda-title { font-size: 2rem !important; margin-bottom: 20px; }
        .project-item { border: 1px solid #000 !important; color: #000 !important; }
    }

    /* Mobile Styles */
    @media (max-width: 768px) {
        body { flex-direction: column; }
        aside { position: fixed; left: 0; top: 0; bottom: 0; transform: translateX(-100%); width: 260px; }
        aside.open { transform: translateX(0); box-shadow: 10px 0 30px rgba(0,0,0,0.5); }
        .mobile-header { display: flex; }
        main { padding: 20px; }
        .grid { grid-template-columns: 1fr; }
        .cal-day-label { font-size: 0.6rem; }
        .project-item { flex-direction: column; align-items: flex-start; gap: 12px; }
        .project-item > div { width: 100%; }
        .section-calendar-grid { grid-template-columns: 1fr !important; }
    }
  </style>
</head>
<body>
  <div class="mobile-header">
    <div style="font-weight: 800; color: var(--primary)">MLB PRO</div>
    <button class="btn-action" onclick="toggleSidebar()">Menu</button>
  </div>

  <div id="sidebar-overlay" class="modal-overlay hidden" style="z-index:950; background:rgba(0,0,0,0.3)" onclick="toggleSidebar()"></div>

  <aside id="sidebar">
    <div style="font-size: 1.5rem; font-weight: 800; margin-bottom: 40px; color: var(--primary); display: flex; justify-content: space-between; align-items: center">
        MLB PRO
    </div>
    <div class="nav-btn active" id="btn-projects" onclick="showSection('projects')">Projects</div>
    <div class="nav-btn" id="btn-inbox" onclick="showSection('inbox')">Inbox <span id="inbox-count" style="background:var(--danger); color:white; padding:2px 6px; border-radius:10px; font-size:0.7rem; margin-left:auto">0</span></div>
    <div class="nav-btn" id="btn-calendar" onclick="showSection('calendar')">Schedule</div>
    <div class="nav-btn" id="btn-users" onclick="showSection('users')">Users</div>
    <div class="nav-btn" id="btn-analytics" onclick="showSection('analytics')">Site Traffic</div>
    <div style="margin-top: auto">
      <form method="post" action="/logout"><button class="btn-action" style="width:100%" type="submit">Logout</button></form>
    </div>
  </aside>

  <main>
    <div class="announcement-bar" id="top-announcement">
        <div id="announcement-text" style="font-weight:600">Loading announcement...</div>
        <button class="btn-action" style="font-size:0.75rem; padding:4px 10px" onclick="editAnnouncement()">Edit</button>
    </div>

    <!-- Projects Section -->
    <div id="section-projects">
      <header><h1>Active Projects</h1><button class="btn-action btn-primary" onclick="openModal()">+ Add Project</button></header>
      <div class="grid">
        <div class="card"><div class="muted" style="font-size:0.8rem">Scheduled</div><div style="font-size:1.5rem; font-weight:700" id="stat-scheduled">0</div></div>
        <div class="card"><div class="muted" style="font-size:0.8rem">In Progress</div><div style="font-size:1.5rem; font-weight:700" id="stat-active">0</div></div>
        <div class="card"><div class="muted" style="font-size:0.8rem">Completed (Month)</div><div style="font-size:1.5rem; font-weight:700" id="stat-done">0</div></div>
      </div>
      <div class="card">
        <div class="section-title">
            Job Board
            <div style="display:flex; gap:12px; align-items:center">
                <input type="text" id="job-search" placeholder="Search name/type..." oninput="renderProjectList()" style="padding:6px 12px; border-radius:6px; border:1px solid var(--border); background:#020617; color:white; font-size:0.85rem">
                <select id="job-filter" onchange="renderProjectList()" style="padding:6px; border-radius:6px; background:#020617; color:white; border:1px solid var(--border); font-size:0.85rem">
                    <option value="All">All Jobs</option>
                    <option value="Approved">Approved</option>
                    <option value="Scheduled">Scheduled</option>
                    <option value="Completed">Completed</option>
                </select>
                <button class="btn-action" style="font-size:0.8rem" onclick="downloadCSV()">Export CSV</button>
            </div>
        </div>
        <div id="project-list"></div>
      </div>
    </div>

    <!-- Inbox Section -->
    <div id="section-inbox" class="hidden">
      <header><h1>Request Inbox</h1></header>
      <div id="inbox-list"></div>
    </div>

    <!-- Calendar Section -->
    <div id="section-calendar" class="hidden">
      <header><h1>Scheduling</h1><button class="btn-action" onclick="window.print()">Print Agenda</button></header>
      <div class="section-calendar-grid" style="display:grid; grid-template-columns: 1.5fr 1fr; gap:24px">
        <div class="card">
          <div class="cal-header">
            <h2 id="cal-month-year">Month Year</h2>
            <div style="display:flex; gap:8px">
              <button class="btn-action" onclick="changeMonth(-1)">←</button>
              <button class="btn-action" onclick="changeMonth(1)">→</button>
            </div>
          </div>
          <div class="cal-grid" id="main-calendar"></div>
        </div>
        <div style="display:flex; flex-direction:column; gap:24px">
          <div class="card">
            <div class="section-title" id="agenda-title">Daily Agenda</div>
            <div id="agenda-list"></div>
          </div>
          <div class="card">
            <div class="section-title">Awaiting Scheduling</div>
            <div id="awaiting-list"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Users Section -->
    <div id="section-users" class="hidden">
      <header><h1>Portal Users</h1><button class="btn-action btn-primary" onclick="openUserModal()">+ Add User</button></header>
      <div class="card">
        <div class="section-title">User Accounts</div>
        <div id="user-list"></div>
      </div>
    </div>

    <!-- Analytics Section -->
    <div id="section-analytics" class="hidden">
        <header><h1>Site Performance</h1></header>
        <div class="grid" id="metrics-container">
            <!-- Dynamic Metrics -->
        </div>
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:24px">
            <div class="card">
                <div class="section-title">Popular Pages (Hits)</div>
                <div id="traffic-list"></div>
            </div>
            <div class="card">
                <div class="section-title">Recent System Activity</div>
                <div id="error-list" style="font-size:0.85rem"></div>
            </div>
        </div>
    </div>
  </main>

  <!-- Job Modal -->
  <div id="job-modal" class="modal-overlay hidden">
    <div class="modal">
        <h2 id="modal-title">Add New Project</h2>
        <input type="hidden" id="edit-id">
        <div class="form-group">
            <label>Client Name</label>
            <input type="text" id="job-name" placeholder="e.g. John Doe">
        </div>
        <div style="display:flex; gap:12px">
            <div class="form-group" style="flex:1">
                <label>Email</label>
                <input type="email" id="job-email" placeholder="client@example.com">
            </div>
            <div class="form-group" style="flex:1">
                <label>Phone</label>
                <input type="text" id="job-phone" placeholder="082 123 4567">
            </div>
        </div>
        <div class="form-group">
            <label>Job Type</label>
            <select id="job-type">
                <option>Solar Quote</option>
                <option>Standard Electrical</option>
                <option>Emergency Call-out</option>
                <option>COC Enquiry</option>
            </select>
        </div>
        <div class="form-group">
            <label>Price Range (Custom)</label>
            <input type="text" id="job-price" placeholder="e.g. R1500 - R2500">
        </div>
        <div style="display:flex; gap:12px">
            <div class="form-group" style="flex:1">
                <label>Scheduled Date</label>
                <input type="date" id="job-date">
            </div>
            <div class="form-group" style="flex:1">
                <label>Scheduled Time</label>
                <input type="time" id="job-time">
            </div>
        </div>
        <div class="form-group">
            <label>Assign To</label>
            <select id="job-assigned"></select>
        </div>
        <div class="form-group">
            <label>Notes / Checklist</label>
            <textarea id="job-notes" rows="4" placeholder="Important details or internal notes..."></textarea>
        </div>
        <div class="form-group">
            <label>Status</label>
            <select id="job-status">
                <option value="Approved">Approved</option>
                <option value="Scheduled">Scheduled</option>
                <option value="Completed">Completed</option>
            </select>
        </div>
        <div style="display:flex; gap:12px; margin-top:24px">
            <button class="btn-action btn-primary" style="flex:1" onclick="saveJob()">Save Job</button>
            <button class="btn-action" style="flex:1" onclick="closeModal()">Cancel</button>
        </div>
    </div>
  </div>

  <!-- User Modal -->
  <div id="user-modal" class="modal-overlay hidden">
    <div class="modal">
        <h2>Add Portal User</h2>
        <div class="form-group">
            <label>Username</label>
            <input type="text" id="user-username" placeholder="e.g. jdoe">
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" id="user-password">
        </div>
        <div class="form-group">
            <label>Role</label>
            <select id="user-role">
                <option value="User">Standard User</option>
                <option value="Owner">Owner (Full Admin)</option>
            </select>
        </div>
        <div style="display:flex; gap:12px; margin-top:24px">
            <button class="btn-action btn-primary" style="flex:1" onclick="saveUser()">Create User</button>
            <button class="btn-action" style="flex:1" onclick="closeUserModal()">Cancel</button>
        </div>
    </div>
  </div>

  <script>
    let projects = [];
    let users = [];
    let currentDate = new Date();
    let selectedDate = new Date();
    let schedulingJobId = null;

    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('open');
        document.getElementById('sidebar-overlay').classList.toggle('hidden');
    }

    function showSection(id) {
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.remove('open');
            document.getElementById('sidebar-overlay').classList.add('hidden');
        }
        ['projects', 'inbox', 'calendar', 'users', 'analytics'].forEach(s => {
            document.getElementById('section-' + s).classList.add('hidden');
            document.getElementById('btn-' + s).classList.remove('active');
        });
        document.getElementById('section-' + id).classList.remove('hidden');
        document.getElementById('btn-' + id).classList.add('active');
        if(id === 'calendar') renderCalendar();
        if(id === 'users') renderUsers();
    }

    async function editAnnouncement() {
        const m = prompt("New site announcement:", document.getElementById('announcement-text').innerText);
        if (m !== null) {
            await fetch(`/api/owner/announcement?m=${encodeURIComponent(m)}`, { method: 'POST' });
            load();
        }
    }

    function openModal(job = null) {
        if (schedulingJobId) cancelScheduling();
        document.getElementById('job-modal').classList.remove('hidden');
        
        const assignSelect = document.getElementById('job-assigned');
        assignSelect.innerHTML = '<option value="All">All Users</option>' + users.map(u => `<option value="${u.username}">${u.username}</option>`).join('');

        if(job) {
            document.getElementById('modal-title').innerText = 'Edit Project';
            document.getElementById('edit-id').value = job.id;
            document.getElementById('job-name').value = job.name;
            document.getElementById('job-email').value = job.email || '';
            document.getElementById('job-phone').value = job.phone || '';
            document.getElementById('job-type').value = job.type;
            document.getElementById('job-price').value = job.priceRange || '';
            document.getElementById('job-notes').value = job.notes || '';
            document.getElementById('job-assigned').value = job.assignedTo || 'All';
            
            if (job.scheduledDate) {
                const dt = new Date(job.scheduledDate);
                document.getElementById('job-date').value = dt.toISOString().split('T')[0];
                document.getElementById('job-time').value = dt.toTimeString().substring(0, 5);
            } else {
                document.getElementById('job-date').value = '';
                document.getElementById('job-time').value = '';
            }
            document.getElementById('job-status').value = job.status;
        } else {
            document.getElementById('modal-title').innerText = 'Add New Project';
            document.getElementById('edit-id').value = '';
            document.getElementById('job-name').value = '';
            document.getElementById('job-email').value = '';
            document.getElementById('job-phone').value = '';
            document.getElementById('job-price').value = '';
            document.getElementById('job-notes').value = '';
            document.getElementById('job-assigned').value = 'All';
            document.getElementById('job-date').value = selectedDate.toISOString().split('T')[0];
            document.getElementById('job-time').value = '09:00';
            document.getElementById('job-status').value = 'Approved';
        }
    }

    function closeModal() { document.getElementById('job-modal').classList.add('hidden'); }

    function downloadCSV() {
        const header = "ID,Name,Type,PriceRange,Date,Status,Phone,Email,Assigned\n";
        const rows = projects.map(p => `${p.id},"${p.name}","${p.type}","${p.priceRange || ''}",${p.scheduledDate || 'TBD'},${p.status},${p.phone || ''},${p.email || ''},${p.assignedTo}`).join("\n");
        const blob = new Blob([header + rows], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `mlb_projects_${new Date().toISOString().split('T')[0]}.csv`; a.click();
    }

    function renderProjectList() {
        const query = document.getElementById('job-search').value.toLowerCase();
        const filter = document.getElementById('job-filter').value;
        const active = projects.filter(p => {
            const matchesQuery = p.name.toLowerCase().includes(query) || p.type.toLowerCase().includes(query);
            const matchesFilter = filter === 'All' || p.status === filter;
            return matchesQuery && matchesFilter && p.status !== 'Pending' && p.status !== 'Declined';
        });

        document.getElementById('project-list').innerHTML = active.map(p => `
            <div class="project-item">
                <div style="flex:1">
                    <div style="font-weight:600">${p.name} <span class="tag ${p.status.toLowerCase()}">${p.status}</span> <span style="font-size:0.7rem; color:var(--primary); font-weight:700">@${p.assignedTo}</span></div>
                    <div class="muted" style="font-size:0.8rem">${p.type} ${p.priceRange ? ' - <span style="color:var(--success); font-weight:700">' + p.priceRange + '</span>' : ''} - ${p.scheduledDate ? new Date(p.scheduledDate).toLocaleDateString() : 'TBD'}</div>
                    ${p.phone ? `<div style="font-size:0.8rem; margin-top:4px">📞 ${p.phone} ${p.email ? '| ✉️ ' + p.email : ''}</div>` : ''}
                    ${p.notes ? `<div style="font-size:0.75rem; color:var(--warning); margin-top:4px">📝 ${p.notes}</div>` : ''}
                </div>
                <div style="display:flex; gap:8px">
                    ${p.phone ? `
                        <a href="tel:${p.phone}" class="btn-action" title="Call Client">📞</a>
                        <a href="https://wa.me/${p.phone.replace(/\s+/g, '')}" target="_blank" class="btn-action" title="WhatsApp Client" style="background:#25D366; border-color:#25D366; color:white">WA</a>
                    ` : ''}
                    <button class="btn-action" onclick='openModal(${JSON.stringify(p).replace(/'/g, "&apos;")})'>Edit</button>
                    <button class="btn-action" style="color:var(--danger)" onclick="deleteJob('${p.id}')">X</button>
                </div>
            </div>
        `).join('') || '<div class="muted">No matching projects.</div>';
    }

    function openUserModal() { document.getElementById('user-modal').classList.remove('hidden'); }
    function closeUserModal() { document.getElementById('user-modal').classList.add('hidden'); }

    async function saveUser() {
        const u = document.getElementById('user-username').value;
        const p = document.getElementById('user-password').value;
        const r = document.getElementById('user-role').value;
        if(!u || !p) return alert('Username and Password required');
        
        await fetch(`/api/owner/users?username=${encodeURIComponent(u)}&password=${encodeURIComponent(p)}&role=${encodeURIComponent(r)}`, { method: 'POST' });
        closeUserModal();
        load();
    }

    async function deleteUser(username) {
        if(confirm('Delete user ' + username + '?')) {
            await fetch(`/api/owner/users/${username}`, { method: 'DELETE' });
            load();
        }
    }

    function renderUsers() {
        document.getElementById('user-list').innerHTML = users.map(u => `
            <div class="project-item">
                <div>
                    <div style="font-weight:600">${u.username} <span class="tag ${u.role.toLowerCase() === 'owner' ? 'approved' : 'scheduled'}">${u.role}</span></div>
                </div>
                <div>
                    <button class="btn-action" style="color:var(--danger)" onclick="deleteUser('${u.username}')">Remove</button>
                </div>
            </div>
        `).join('') || '<div class="muted">No other users.</div>';
    }

    async function saveJob() {
        const id = document.getElementById('edit-id').value;
        const name = document.getElementById('job-name').value;
        const email = document.getElementById('job-email').value;
        const phone = document.getElementById('job-phone').value;
        const type = document.getElementById('job-type').value;
        const priceRange = document.getElementById('job-price').value;
        const date = document.getElementById('job-date').value;
        const time = document.getElementById('job-time').value;
        const status = document.getElementById('job-status').value;
        const notes = document.getElementById('job-notes').value;

        if(!name) return alert('Name is required');

        const dateTime = (date && time) ? `${date}T${time}` : date;

        const method = id ? 'PUT' : 'POST';
        const url = id ? `/api/owner/projects/${id}?name=${encodeURIComponent(name)}&email=${encodeURIComponent(email)}&phone=${encodeURIComponent(phone)}&type=${encodeURIComponent(type)}&priceRange=${encodeURIComponent(priceRange)}&date=${encodeURIComponent(dateTime)}&status=${encodeURIComponent(status)}&notes=${encodeURIComponent(notes)}` 
                       : `/api/owner/projects?name=${encodeURIComponent(name)}&email=${encodeURIComponent(email)}&phone=${encodeURIComponent(phone)}&type=${encodeURIComponent(type)}&priceRange=${encodeURIComponent(priceRange)}&date=${encodeURIComponent(dateTime)}`;
        
        await fetch(url, { method });
        closeModal();
        load();
    }

    async function deleteJob(id) {
        if(confirm('Are you sure you want to delete this job?')) {
            await fetch(`/api/owner/projects/${id}`, { method: 'DELETE' });
            load();
        }
    }

    async function updateStatus(id, status, date = null) {
        let url = `/api/owner/projects/${id}/status?status=${encodeURIComponent(status)}`;
        if(date) url += `&date=${encodeURIComponent(date)}`;
        await fetch(url, { method: 'POST' });
        load();
    }

    function changeMonth(delta) {
        currentDate.setMonth(currentDate.getMonth() + delta);
        renderCalendar();
    }

    async function selectDay(d) {
        const newDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), d);
        if (schedulingJobId) {
            const dateStr = `${newDate.getFullYear()}-${String(newDate.getMonth()+1).padStart(2,'0')}-${String(d).padStart(2,'0')}T09:00`;
            const job = projects.find(p => p.id === schedulingJobId);
            if (job) {
                await updateStatus(schedulingJobId, 'Scheduled', dateStr);
                schedulingJobId = null;
                selectedDate = newDate;
                renderCalendar();
                return;
            }
        }
        selectedDate = newDate;
        renderCalendar();
    }

    function startScheduling(id) {
        schedulingJobId = id;
        renderCalendar();
        renderAgenda();
    }

    function cancelScheduling() {
        schedulingJobId = null;
        renderCalendar();
        renderAgenda();
    }

    function renderCalendar() {
        const cal = document.getElementById('main-calendar');
        const monthLabel = document.getElementById('cal-month-year');
        cal.innerHTML = '';
        
        monthLabel.innerText = new Intl.DateTimeFormat('en-US', { month: 'long', year: 'numeric' }).format(currentDate);
        ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].forEach(d => cal.innerHTML += `<div class="cal-day-label">${d}</div>`);
        
        const firstDay = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1).getDay();
        const daysInMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0).getDate();
        
        for(let i=0; i<firstDay; i++) cal.innerHTML += '<div></div>';
        
        const today = new Date();
        const schedJob = schedulingJobId ? projects.find(p => p.id === schedulingJobId) : null;

        for(let d=1; d<=daysInMonth; d++) {
            const dateStr = `${currentDate.getFullYear()}-${String(currentDate.getMonth()+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
            const dayJobs = projects.filter(p => p.scheduledDate && p.scheduledDate.startsWith(dateStr))
                                    .sort((a, b) => (a.scheduledDate || '').localeCompare(b.scheduledDate || ''));
            const hasJob = dayJobs.length > 0;
            
            const isToday = today.getFullYear() === currentDate.getFullYear() && 
                            today.getMonth() === currentDate.getMonth() && 
                            today.getDate() === d;
            
            const isSelected = selectedDate.getFullYear() === currentDate.getFullYear() && 
                               selectedDate.getMonth() === currentDate.getMonth() && 
                               selectedDate.getDate() === d;
            
            const dayEl = document.createElement('div');
            dayEl.className = `cal-day ${hasJob ? 'has-job' : ''} ${isToday ? 'today' : ''} ${isSelected ? 'active' : ''}`;
            
            // Drag & Drop for Days (Drop Targets)
            dayEl.ondragover = (e) => { e.preventDefault(); dayEl.classList.add('drag-over'); };
            dayEl.ondragleave = () => dayEl.classList.remove('drag-over');
            dayEl.ondrop = async (e) => {
                e.preventDefault();
                dayEl.classList.remove('drag-over');
                const jobId = e.dataTransfer.getData('jobId');
                if (jobId) {
                    const targetDateStr = `${currentDate.getFullYear()}-${String(currentDate.getMonth()+1).padStart(2,'0')}-${String(d).padStart(2,'0')}T09:00`;
                    await updateStatus(jobId, 'Scheduled', targetDateStr);
                }
            };

            if (schedulingJobId) {
                dayEl.style.cursor = 'crosshair';
                dayEl.title = `Click to schedule ${schedJob?.name} here`;
            }
            dayEl.innerHTML = `<span style="font-weight:700">${d}</span>`;
            
            if (hasJob) {
                dayJobs.slice(0, 4).forEach(job => {
                    const jobEl = document.createElement('div');
                    jobEl.className = 'cal-job';
                    jobEl.draggable = true;
                    jobEl.innerText = job.name;
                    jobEl.title = `${job.name} (${job.type})`;
                    
                    // Drag Start
                    jobEl.ondragstart = (e) => {
                        e.dataTransfer.setData('jobId', job.id);
                        jobEl.style.opacity = '0.5';
                    };
                    jobEl.ondragend = () => jobEl.style.opacity = '1';

                    jobEl.onclick = (e) => { e.stopPropagation(); openModal(job); };
                    dayEl.appendChild(jobEl);
                });
                if (dayJobs.length > 4) {
                    const moreEl = document.createElement('div');
                    moreEl.style = 'font-size:0.55rem; color:var(--muted); margin-top:1px';
                    moreEl.innerText = `+${dayJobs.length - 4} more`;
                    dayEl.appendChild(moreEl);
                }
            }

            dayEl.onclick = () => selectDay(d);
            cal.appendChild(dayEl);
        }
        renderAgenda();
    }

    function renderAgenda() {
        const dateStr = `${selectedDate.getFullYear()}-${String(selectedDate.getMonth()+1).padStart(2,'0')}-${String(selectedDate.getDate()).padStart(2,'0')}`;
        
        let agendaTitle = 'Agenda for ' + selectedDate.toLocaleDateString();
        if (schedulingJobId) {
            const p = projects.find(x => x.id === schedulingJobId);
            agendaTitle = `<span style="color:var(--primary)">Scheduling: ${p?.name}</span> <button class="btn-action" style="font-size:0.7rem; padding:2px 8px" onclick="cancelScheduling()">Cancel</button>`;
        }
        document.getElementById('agenda-title').innerHTML = agendaTitle;
        
        const dayJobs = projects.filter(p => p.scheduledDate && p.scheduledDate.startsWith(dateStr))
                                .sort((a, b) => (a.scheduledDate || '').localeCompare(b.scheduledDate || ''));
        
        let html = dayJobs.map(p => {
            const timeStr = p.scheduledDate && p.scheduledDate.includes('T') ? new Date(p.scheduledDate).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Anytime';
            return `
            <div class="project-item" style="flex-direction:column; align-items:flex-start">
                <div style="width:100%; display:flex; justify-content:space-between">
                    <strong>[${timeStr}] ${p.name}</strong>
                    <span class="tag ${p.status.toLowerCase()}">${p.status}</span>
                </div>
                <div class="muted" style="font-size:0.8rem; margin:4px 0 8px 0">${p.type}</div>
                ${p.phone ? `<div style="font-size:0.8rem; margin-bottom:8px">📞 ${p.phone} ${p.email ? '| ✉️ ' + p.email : ''}</div>` : ''}
                ${p.notes ? `<div style="font-size:0.8rem; background:rgba(255,255,255,0.05); padding:8px; border-radius:4px; margin-bottom:12px; width:100%">${p.notes}</div>` : ''}
                <div style="display:flex; gap:8px; width:100%">
                    <button class="btn-action" style="font-size:0.75rem" onclick='openModal(${JSON.stringify(p).replace(/'/g, "&apos;")})'>Edit</button>
                    ${p.phone ? `<a href="https://wa.me/${p.phone.replace(/\s+/g, '')}" target="_blank" class="btn-action" style="font-size:0.75rem; background:#25D366; border-color:#25D366; color:white">WhatsApp</a>` : ''}
                    <button class="btn-action" style="font-size:0.75rem; color:var(--danger)" onclick="deleteJob('${p.id}')">Delete</button>
                    ${p.status === 'Scheduled' ? `<button class="btn-action" style="font-size:0.75rem; color:var(--success)" onclick="updateStatus('${p.id}', 'Completed')">Done</button>` : ''}
                </div>
            </div>
        `; }).join('');

        html += `<button class="btn-action" style="width:100%; margin-top:12px; border-style:dashed" onclick="openModal()">+ Add New Job for this Date</button>`;
        document.getElementById('agenda-list').innerHTML = html;

        // Populate Awaiting List
        const awaiting = projects.filter(p => p.status === 'Pending' || p.status === 'Approved');
        document.getElementById('awaiting-list').innerHTML = awaiting.map(p => `
            <div class="project-item" style="font-size:0.85rem; border-color: ${schedulingJobId === p.id ? 'var(--primary)' : 'var(--border)'}">
                <div style="flex:1">
                    <strong>${p.name}</strong>
                    <div class="muted" style="font-size:0.75rem">${p.type}</div>
                </div>
                <button class="btn-action" style="font-size:0.7rem; background:${schedulingJobId === p.id ? 'var(--danger)' : 'var(--primary)'}; color:white; border:0" onclick="${schedulingJobId === p.id ? 'cancelScheduling()' : `startScheduling('${p.id}')`}">
                    ${schedulingJobId === p.id ? 'Cancel' : 'Schedule'}
                </button>
            </div>
        `).join('') || '<div class="muted" style="font-size:0.8rem">No pending jobs.</div>';
    }

    async function load() {
        projects = await fetch('/api/owner/projects').then(r => r.json());
        users = await fetch('/api/owner/users').then(r => r.json());
        const analytics = await fetch('/api/owner/analytics').then(r => r.json());
        const announcement = await fetch('/api/announcement').then(r => r.json());

        document.getElementById('announcement-text').innerText = announcement.message;

        const pending = projects.filter(p => p.status === 'Pending');
        document.getElementById('inbox-count').innerText = pending.length;
        document.getElementById('inbox-list').innerHTML = pending.map(p => `
            <div class="project-item">
                <div><div style="font-weight:600">${p.name} <span class="tag pending">${p.type}</span></div><div class="muted" style="font-size:0.8rem">${p.phone} | ${p.email}</div><div style="margin-top:8px">${p.message}</div></div>
                <div style="display:flex; gap:8px"><button class="btn-action" style="color:var(--success)" onclick="updateStatus('${p.id}', 'Approved')">Approve</button><button class="btn-action" style="color:var(--danger)" onclick="updateStatus('${p.id}', 'Declined')">Decline</button></div>
            </div>
        `).join('') || '<div class="muted">No new requests.</div>';

        renderProjectList();
        document.getElementById('stat-scheduled').innerText = projects.filter(p => p.status === 'Scheduled').length;
        document.getElementById('stat-active').innerText = projects.filter(p => p.status === 'Approved').length;
        document.getElementById('stat-done').innerText = projects.filter(p => p.status === 'Completed').length;

        document.getElementById('metrics-container').innerHTML = `
            <div class="card"><div class="muted" style="font-size:0.8rem">Total Requests</div><div style="font-size:1.5rem; font-weight:700">${analytics.totalRequests}</div></div>
            <div class="card"><div class="muted" style="font-size:0.8rem">Portal Logins</div><div style="font-size:1.5rem; font-weight:700">${analytics.totalLogins}</div></div>
            <div class="card"><div class="muted" style="font-size:0.8rem">Unique Visitors</div><div style="font-size:1.5rem; font-weight:700">${analytics.uniqueVisitors}</div></div>
            <div class="card"><div class="muted" style="font-size:0.8rem">Server Uptime</div><div style="font-size:1.5rem; font-weight:700">${Math.floor(analytics.uptimeSeconds/3600)}h ${Math.floor((analytics.uptimeSeconds%3600)/60)}m</div></div>
        `;
        document.getElementById('traffic-list').innerHTML = analytics.topRoutes.map(r => `<div style="display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--border)"><span style="font-family:monospace; font-size:0.9rem">${r.route}</span><span style="font-weight:700; color:var(--primary)">${r.hits}</span></div>`).join('') || '<div class="muted">No traffic.</div>';
        document.getElementById('login-history').innerHTML = analytics.loginHistory.map(l => `<div style="padding:6px 0; border-bottom:1px solid var(--border)">${l}</div>`).join('') || '<div class="muted">No logins.</div>';
        document.getElementById('error-list').innerHTML = analytics.recentErrors.map(e => `<div style="padding:6px 0; color:var(--danger); border-bottom:1px solid var(--border)">${e}</div>`).join('') || '<div class="muted">No errors.</div>';

        renderCalendar(); renderUsers();
    }
    load(); setInterval(load, 20000);
    </script>
    </body>
    </html>
""";

    public const string UserDashboardHtml = """
    <!doctype html>
    <html lang="en">
    <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>User Dashboard | MLB</title>
    <style>
    :root { --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0; --text: #1e293b; --muted: #64748b; --primary: #3b82f6; }
    body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:24px;line-height:1.5}
    .container { max-width: 1100px; margin: 0 auto; }
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;padding-bottom:16px;border-bottom:1px solid var(--border)}
    .announcement { background: #dbe8ff; color: #1e40af; padding: 12px 20px; border-radius: 12px; margin-bottom: 32px; font-weight: 600; border-left: 6px solid var(--primary); }
    .grid{display:grid;grid-template-columns: 1.5fr 1fr;gap:24px;margin-bottom:32px}
    .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1)}
    h2{font-size:1.1rem;margin:0 0 20px 0;display:flex;align-items:center;gap:8px}
    .btn-logout { padding:8px 16px; border:1px solid var(--border); border-radius:8px; background:white; color:var(--text); cursor:pointer; font-weight:500; }

    .cal-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
    .cal-grid { display:grid; grid-template-columns:repeat(7,1fr); gap:4px; }
    .cal-day-label { text-align:center; font-size:0.75rem; font-weight:600; color:var(--muted); padding:8px 0; }
    .cal-day { aspect-ratio:1; display:flex; flex-direction:column; align-items:center; justify-content:center; border:1px solid var(--border); border-radius:6px; font-size:0.875rem; cursor:pointer; transition:all 0.2s; position:relative; }
    .cal-day:hover { background:var(--bg); border-color:var(--primary); }
    .cal-day.today { background:var(--primary); color:white; border-color:var(--primary); font-weight:700; }
    .cal-day.has-event::after { content:''; width:4px; height:4px; background:var(--primary); border-radius:50%; position:absolute; bottom:4px; }
    .cal-day.today.has-event::after { background:white; }

    .event-list { margin-top:20px; }
    .event-item { padding:16px; border-left:4px solid var(--primary); background:var(--bg); border-radius:0 8px 8px 0; margin-bottom:12px; font-size:0.95rem; }
    .event-time { font-size:0.75rem; color:var(--muted); font-weight:700; text-transform: uppercase; margin-bottom: 4px; }
    .diagnostics { font-family:monospace; font-size:0.8rem; color:var(--muted); margin-top:16px; padding:12px; background:var(--bg); border-radius:6px; }

    @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
    </style>
    </head>
    <body>
    <div class="container">
    <div class="announcement" id="site-announcement">Loading portal updates...</div>
    <header>
      <h1>Task Dashboard</h1>
      <form method="post" action="/logout"><button class="btn-logout" type="submit">Logout</button></form>
    </header>

    <div class="grid">
      <div class="card">
        <div class="cal-header">
          <h2 id="month-year">My Schedule</h2>
          <div style="display:flex;gap:8px"><button class="btn-logout" onclick="prevMonth()">←</button><button class="btn-logout" onclick="nextMonth()">→</button></div>
        </div>
        <div class="cal-grid" id="calendar"></div>
        <div class="event-list">
          <h2 id="selected-date-label">Schedule</h2>
          <div id="events-container"></div>
        </div>
      </div>

      <div class="card">
        <h2>System Status</h2>
        <div id="diag-summary">Loading...</div>
        <div class="diagnostics" id="runtime"></div>
        <h2 style="margin-top:24px">Connectivity Activity</h2>
        <div id="activity-list" style="font-size:0.85rem"></div>
      </div>
    </div>
    </div>

    <script>
    let currentDate = new Date();
    let selectedDateStr = new Date().toISOString().split('T')[0];
    let myProjects = [];

    function renderCalendar() {
      const cal = document.getElementById('calendar');
      cal.innerHTML = '';
      document.getElementById('month-year').innerText = new Intl.DateTimeFormat('en-US', { month: 'long', year: 'numeric' }).format(currentDate);
      ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].forEach(d => cal.innerHTML += `<div class="cal-day-label">${d}</div>`);
      const firstDay = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1).getDay();
      const daysInMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0).getDate();
      for(let i=0; i<firstDay; i++) cal.innerHTML += '<div></div>';
      const today = new Date();
      for(let d=1; d<=daysInMonth; d++) {
        const dateStr = `${currentDate.getFullYear()}-${String(currentDate.getMonth()+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
        const isToday = today.getFullYear() === currentDate.getFullYear() && today.getMonth() === currentDate.getMonth() && today.getDate() === d;
        const hasEvent = myProjects.some(p => p.scheduledDate && p.scheduledDate.startsWith(dateStr));
        const dayEl = document.createElement('div');
        dayEl.className = `cal-day ${isToday ? 'today' : ''} ${hasEvent ? 'has-event' : ''}`;
        dayEl.innerText = d; dayEl.onclick = () => selectDate(dateStr); cal.appendChild(dayEl);
      }
      selectDate(selectedDateStr);
    }

    function selectDate(dateStr) {
      selectedDateStr = dateStr;
      document.getElementById('selected-date-label').innerText = 'Tasks for ' + new Date(dateStr).toLocaleDateString();
      const container = document.getElementById('events-container');
      const dayJobs = myProjects.filter(p => p.scheduledDate && p.scheduledDate.startsWith(dateStr));
      container.innerHTML = dayJobs.map(p => {
        const time = p.scheduledDate.includes('T') ? new Date(p.scheduledDate).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : 'Anytime';
        return `<div class="event-item">
            <div class="event-time">${time} ${p.priceRange ? ' | <span style="color:var(--primary)">' + p.priceRange + '</span>' : ''}</div>
            <div style="font-weight:700">${p.name}</div>
            <div style="color:var(--muted); font-size:0.85rem">${p.type}</div>
            ${p.notes?`<div style="margin-top:8px; font-size:0.85rem; background:#fff; border:1px solid var(--border); padding:8px; border-radius:4px">${p.notes}</div>`:''}
        </div>`;
      }).join('') || '<div class="muted">Nothing scheduled for this day.</div>';
    }


    function prevMonth() { currentDate.setMonth(currentDate.getMonth() - 1); renderCalendar(); }
    function nextMonth() { currentDate.setMonth(currentDate.getMonth() + 1); renderCalendar(); }

    async function load() {
      try {
        const [projects, diagnostics, announcement] = await Promise.all([
            fetch('/api/user/my-projects').then(r => r.json()),
            fetch('/api/user/diagnostics').then(r => r.json()),
            fetch('/api/announcement').then(r => r.json())
        ]);
        myProjects = projects;
        document.getElementById('site-announcement').innerText = announcement.message;
        document.getElementById('diag-summary').innerHTML = `<div><strong>Site Traffic:</strong> ${diagnostics.totalRequests} hits</div>`;
        document.getElementById('runtime').innerText = `Server OS: ${diagnostics.os} | Host: ${diagnostics.machine}`;
        document.getElementById('activity-list').innerHTML = diagnostics.recentStatuses.map(s => `<div style="padding:6px 0; border-bottom:1px solid var(--border)">${s}</div>`).join('') || 'No activity.';
        renderCalendar();
      } catch (e) { console.error(e); }
    }
    load(); setInterval(load, 15000);
    </script>
    </body>
    </html>
""";
}
