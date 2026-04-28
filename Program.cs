using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/login";
        options.Cookie.Name = "mlb.auth";
        options.ExpireTimeSpan = TimeSpan.FromHours(12);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("OwnerOnly", policy => policy.RequireRole("Owner"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User", "Owner"));
});

builder.Services.AddSingleton<RequestAnalyticsStore>();

var app = builder.Build();
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

app.MapGet("/login", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect(context.User.IsInRole("Owner") ? "/owner/dashboard" : "/user/dashboard");
    }

    return Results.Content(HtmlTemplates.LoginPageHtml, "text/html");
});

app.MapPost("/login", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = (form["username"].ToString() ?? string.Empty).Trim();
    var password = form["password"].ToString() ?? string.Empty;

    var matchedUser = users.FirstOrDefault(u =>
        string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(u.Password, password, StringComparison.Ordinal));

    if (matchedUser is null)
    {
        return Results.Content(HtmlTemplates.LoginPageHtml.Replace("{{ERROR}}", "Invalid username or password."), "text/html");
    }

    var claims = new List<Claim>
    {
        new(ClaimTypes.Name, matchedUser.Username),
        new(ClaimTypes.Role, matchedUser.Role)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    return Results.Redirect(matchedUser.Role.Equals("Owner", StringComparison.OrdinalIgnoreCase)
        ? "/owner/dashboard"
        : "/user/dashboard");
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

app.MapGet("/api/owner/analytics", [Authorize(Policy = "OwnerOnly")] (RequestAnalyticsStore analytics) =>
{
    var snapshot = analytics.GetSnapshot();
    return Results.Json(new
    {
        uptimeMinutes = Math.Round((DateTimeOffset.UtcNow - startTime).TotalMinutes, 1),
        snapshot.TotalRequests,
        snapshot.UniqueVisitors,
        snapshot.Status2xx,
        snapshot.Status4xx,
        snapshot.Status5xx,
        topRoutes = snapshot.RouteHits
            .OrderByDescending(x => x.Value)
            .Take(8)
            .Select(x => new { route = x.Key, hits = x.Value }),
        recentErrors = snapshot.RecentErrors.Take(10)
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
            .OrderByDescending(x => x.Value)
            .Take(8)
            .Select(x => new { route = x.Key, avgMs = Math.Round(x.Value, 1) }),
        recentStatuses = snapshot.RecentStatuses.Take(15)
    });
});

app.UseDefaultFiles();
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(app.Environment.ContentRootPath),
    RequestPath = ""
});

app.Run();

internal sealed class PortalUser
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Role { get; set; } = "";
}

internal sealed class RequestAnalyticsStore
{
    private readonly ConcurrentDictionary<string, int> _routeHits = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _visitorHits = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (double totalMs, int count)> _routeDuration = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<string> _recentErrors = new();
    private readonly ConcurrentQueue<string> _recentStatuses = new();

    private int _totalRequests;
    private int _status2xx;
    private int _status4xx;
    private int _status5xx;

    public void TrackRequest(string path, string ip)
    {
        _routeHits.AddOrUpdate(path, 1, (_, value) => value + 1);
        _visitorHits.AddOrUpdate(ip, 1, (_, value) => value + 1);
        Interlocked.Increment(ref _totalRequests);
    }

    public void TrackResponse(string path, int statusCode, long elapsedMs)
    {
        if (statusCode is >= 200 and < 300)
        {
            Interlocked.Increment(ref _status2xx);
        }
        else if (statusCode is >= 400 and < 500)
        {
            Interlocked.Increment(ref _status4xx);
        }
        else if (statusCode >= 500)
        {
            Interlocked.Increment(ref _status5xx);
        }

        _routeDuration.AddOrUpdate(path, (elapsedMs, 1), (_, current) => (current.totalMs + elapsedMs, current.count + 1));
        EnqueueBounded(_recentStatuses, $"{DateTimeOffset.UtcNow:HH:mm:ss} | {statusCode} | {path}");
    }

    public void TrackException(string path, string message)
    {
        EnqueueBounded(_recentErrors, $"{DateTimeOffset.UtcNow:HH:mm:ss} | {path} | {message}");
    }

    public AnalyticsSnapshot GetSnapshot()
    {
        return new AnalyticsSnapshot(
            Interlocked.CompareExchange(ref _totalRequests, 0, 0),
            _visitorHits.Count,
            Interlocked.CompareExchange(ref _status2xx, 0, 0),
            Interlocked.CompareExchange(ref _status4xx, 0, 0),
            Interlocked.CompareExchange(ref _status5xx, 0, 0),
            new Dictionary<string, int>(_routeHits),
            _routeDuration.ToDictionary(x => x.Key, x => x.Value.count == 0 ? 0 : x.Value.totalMs / x.Value.count),
            _recentErrors.Reverse().ToList(),
            _recentStatuses.Reverse().ToList());
    }

    private static void EnqueueBounded(ConcurrentQueue<string> queue, string value)
    {
        queue.Enqueue(value);
        while (queue.Count > 40)
        {
            queue.TryDequeue(out _);
        }
    }
}

internal sealed record AnalyticsSnapshot(
    int TotalRequests,
    int UniqueVisitors,
    int Status2xx,
    int Status4xx,
    int Status5xx,
    Dictionary<string, int> RouteHits,
    Dictionary<string, double> RouteDurations,
    List<string> RecentErrors,
    List<string> RecentStatuses);

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
    input{width:100%;padding:10px;border-radius:10px;border:1px solid #355f99;background:#0c1a31;color:#fff}
    button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:10px;background:#0056b3;color:#fff;font-weight:700}
    .error{color:#ff9aa6;min-height:20px}
  </style>
</head>
<body>
  <form class="card" method="post" action="/login">
    <h1>Portal Login</h1>
    <p>Use your Owner or User credentials.</p>
    <div class="error">{{ERROR}}</div>
    <label for="username">Username</label>
    <input id="username" name="username" required />
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required />
    <button type="submit">Sign In</button>
  </form>
</body>
</html>
""";

public const string OwnerDashboardHtml = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Owner Dashboard</title>
  <style>
    body{font-family:Arial,sans-serif;background:#061122;color:#e8f0ff;margin:0;padding:20px}
    .bar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
    .card{background:#0d1b33;border:1px solid #294f84;border-radius:12px;padding:14px}
    h1,h2{margin:0 0 8px}
    .muted{color:#9cb5d9}
    ul{margin:8px 0 0;padding-left:18px}
    button{padding:8px 12px;border:0;border-radius:8px;background:#0056b3;color:#fff}
  </style>
</head>
<body>
  <div class="bar">
    <h1>Owner Dashboard</h1>
    <form method="post" action="/logout"><button type="submit">Logout</button></form>
  </div>
  <div class="grid" id="metrics"></div>
  <div class="card" style="margin-top:12px">
    <h2>Top Traffic Routes</h2>
    <ul id="routes"></ul>
  </div>
  <div class="card" style="margin-top:12px">
    <h2>Recent Errors</h2>
    <ul id="errors"></ul>
  </div>
  <script>
    async function load() {
      const data = await fetch('/api/owner/analytics').then(r => r.json());
      const cards = [
        ['Uptime (min)', data.uptimeMinutes],
        ['Total Requests', data.totalRequests],
        ['Unique Visitors', data.uniqueVisitors],
        ['2xx Responses', data.status2xx],
        ['4xx Responses', data.status4xx],
        ['5xx Responses', data.status5xx]
      ];
      document.getElementById('metrics').innerHTML = cards.map(c => `<div class="card"><div class="muted">${c[0]}</div><strong>${c[1]}</strong></div>`).join('');
      document.getElementById('routes').innerHTML = data.topRoutes.map(r => `<li>${r.route} - ${r.hits}</li>`).join('') || '<li>No traffic yet.</li>';
      document.getElementById('errors').innerHTML = data.recentErrors.map(r => `<li>${r}</li>`).join('') || '<li>No recent errors.</li>';
    }
    load();
    setInterval(load, 15000);
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
  <title>User Dashboard</title>
  <style>
    body{font-family:Arial,sans-serif;background:#061122;color:#e8f0ff;margin:0;padding:20px}
    .bar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:18px}
    .card{background:#0d1b33;border:1px solid #294f84;border-radius:12px;padding:14px;margin-bottom:12px}
    h1,h2{margin:0 0 8px}
    ul{margin:8px 0 0;padding-left:18px}
    .mono{font-family:Consolas,monospace;color:#9fd0ff}
    button{padding:8px 12px;border:0;border-radius:8px;background:#0056b3;color:#fff}
  </style>
</head>
<body>
  <div class="bar">
    <h1>User Dashboard</h1>
    <form method="post" action="/logout"><button type="submit">Logout</button></form>
  </div>
  <div class="card">
    <h2>Runtime Details</h2>
    <div id="runtime" class="mono">Loading...</div>
  </div>
  <div class="card">
    <h2>Slowest Routes (avg ms)</h2>
    <ul id="slow"></ul>
  </div>
  <div class="card">
    <h2>Recent Statuses</h2>
    <ul id="status"></ul>
  </div>
  <script>
    async function load() {
      const data = await fetch('/api/user/diagnostics').then(r => r.json());
      document.getElementById('runtime').innerText =
        `env=${data.environment} | machine=${data.machine} | os=${data.os} | dotnet=${data.dotnet} | totalRequests=${data.totalRequests}`;
      document.getElementById('slow').innerHTML = data.recentSlowRoutes.map(r => `<li>${r.route} - ${r.avgMs}ms</li>`).join('') || '<li>No data yet.</li>';
      document.getElementById('status').innerHTML = data.recentStatuses.map(r => `<li>${r}</li>`).join('') || '<li>No requests yet.</li>';
    }
    load();
    setInterval(load, 10000);
  </script>
</body>
</html>
""";
}
