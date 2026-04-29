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
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
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

app.MapGet("/login", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        return Results.Redirect(context.User.IsInRole("Owner") ? "/owner/dashboard" : "/user/dashboard");
    }

    return Results.Content(HtmlTemplates.LoginPageHtml.Replace("{{ERROR}}", ""), "text/html");
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
    var noise = new[] { "/favicon.ico", "/api/owner/analytics", "/api/user/diagnostics", "/.well-known" };
    
    return Results.Json(new
    {
        uptimeSeconds = (int)(DateTimeOffset.UtcNow - startTime).TotalSeconds,
        snapshot.TotalRequests,
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
  <title>Owner Dashboard | MLB</title>
  <style>
    :root { --bg: #060d1a; --card: #0f172a; --border: #1e293b; --text: #f8fafc; --muted: #94a3b8; --primary: #3b82f6; --success: #22c55e; --danger: #ef4444; }
    body{font-family:'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:24px;line-height:1.5}
    .container { max-width: 1100px; margin: 0 auto; }
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;padding-bottom:16px;border-bottom:1px solid var(--border)}
    h1{margin:0;font-size:1.5rem;font-weight:600}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:20px;margin-bottom:32px}
    .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1)}
    .card-label{color:var(--muted);font-size:0.875rem;font-weight:500;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.025em}
    .card-value{font-size:1.875rem;font-weight:700}
    .status-pill { display: inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:99px; font-size:0.875rem; font-weight:600; background:rgba(34,197,94,0.1); color:var(--success); }
    .status-pill.danger { background:rgba(239,68,68,0.1); color:var(--danger); }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th { text-align: left; color: var(--muted); font-size: 0.75rem; text-transform: uppercase; padding: 12px 0; border-bottom: 1px solid var(--border); }
    td { padding: 14px 0; border-bottom: 1px solid var(--border); font-size: 0.95rem; }
    .route-name { font-family: monospace; color: var(--primary); }
    .btn-logout { padding:8px 16px; border:1px solid var(--border); border-radius:8px; background:transparent; color:var(--text); cursor:pointer; font-weight:500; transition:all 0.2s; }
    .btn-logout:hover { background:var(--border); }
    .empty { color: var(--muted); font-style: italic; padding: 20px 0; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>Owner Dashboard</h1>
        <div id="health" class="status-pill">System Healthy</div>
      </div>
      <form method="post" action="/logout"><button class="btn-logout" type="submit">Logout</button></form>
    </header>
    
    <div class="grid" id="metrics">
      <div class="card"><div class="card-label">Uptime</div><div class="card-value" id="val-uptime">0s</div></div>
      <div class="card"><div class="card-label">Total Requests</div><div class="card-value" id="val-requests">0</div></div>
      <div class="card"><div class="card-label">Unique Visitors</div><div class="card-value" id="val-visitors">0</div></div>
      <div class="card"><div class="card-label">Success Rate</div><div class="card-value" id="val-rate">100%</div></div>
    </div>

    <div style="display:grid;grid-template-columns: 1.5fr 1fr; gap:24px;">
      <div class="card">
        <h2 style="font-size:1.1rem;margin-top:0">Top Traffic (Page Views)</h2>
        <table id="tbl-routes">
          <thead><tr><th>Route Path</th><th style="text-align:right">Hits</th></tr></thead>
          <tbody id="routes-body"></tbody>
        </table>
      </div>
      <div class="card">
        <h2 style="font-size:1.1rem;margin-top:0">System Errors</h2>
        <div id="errors-list" style="font-size:0.85rem"></div>
      </div>
    </div>
  </div>

  <script>
    function formatUptime(sec) {
      const d = Math.floor(sec / 86400);
      const h = Math.floor((sec % 86400) / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = sec % 60;
      let res = '';
      if(d > 0) res += d + 'd ';
      if(h > 0 || d > 0) res += h + 'h ';
      res += m + 'm ' + s + 's';
      return res;
    }

    async function load() {
      try {
        const data = await fetch('/api/owner/analytics').then(r => r.json());
        document.getElementById('val-uptime').innerText = formatUptime(data.uptimeSeconds);
        document.getElementById('val-requests').innerText = data.totalRequests;
        document.getElementById('val-visitors').innerText = data.uniqueVisitors;
        
        const rate = data.totalRequests === 0 ? 100 : Math.round((data.status2xx / data.totalRequests) * 100);
        document.getElementById('val-rate').innerText = rate + '%';
        
        const health = document.getElementById('health');
        if(data.status5xx > 0 || rate < 80) {
          health.innerText = 'Degraded Performance';
          health.className = 'status-pill danger';
        } else {
          health.innerText = 'System Healthy';
          health.className = 'status-pill';
        }

        document.getElementById('routes-body').innerHTML = data.topRoutes.map(r => 
          `<tr><td class="route-name">${r.route}</td><td style="text-align:right"><strong>${r.hits}</strong></td></tr>`
        ).join('') || '<tr><td colspan="2" class="empty">No traffic recorded yet.</td></tr>';

        document.getElementById('errors-list').innerHTML = data.recentErrors.map(e => 
          `<div style="padding:8px 0;border-bottom:1px solid var(--border);color:var(--danger)">${e}</div>`
        ).join('') || '<div class="empty">No recent system errors.</div>';
      } catch (e) { console.error(e); }
    }
    load();
    setInterval(load, 5000);
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
    body{font-family:'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);margin:0;padding:24px;line-height:1.5}
    .container { max-width: 1100px; margin: 0 auto; }
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;padding-bottom:16px;border-bottom:1px solid var(--border)}
    h1{margin:0;font-size:1.5rem;font-weight:600}
    .grid{display:grid;grid-template-columns: 1.5fr 1fr;gap:24px;margin-bottom:32px}
    .card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1)}
    h2{font-size:1.1rem;margin:0 0 20px 0;display:flex;align-items:center;gap:8px}
    .btn-logout { padding:8px 16px; border:1px solid var(--border); border-radius:8px; background:white; color:var(--text); cursor:pointer; font-weight:500; }
    
    /* Calendar Styles */
    .cal-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
    .cal-grid { display:grid; grid-template-columns:repeat(7,1fr); gap:4px; }
    .cal-day-label { text-align:center; font-size:0.75rem; font-weight:600; color:var(--muted); padding:8px 0; }
    .cal-day { aspect-ratio:1; display:flex; flex-direction:column; align-items:center; justify-content:center; border:1px solid var(--border); border-radius:6px; font-size:0.875rem; cursor:pointer; transition:all 0.2s; position:relative; }
    .cal-day:hover { background:var(--bg); border-color:var(--primary); }
    .cal-day.today { background:var(--primary); color:white; border-color:var(--primary); font-weight:700; }
    .cal-day.has-event::after { content:''; width:4px; height:4px; background:var(--primary); border-radius:50%; position:absolute; bottom:4px; }
    .cal-day.today.has-event::after { background:white; }
    
    .event-list { margin-top:20px; }
    .event-item { padding:12px; border-left:4px solid var(--primary); background:var(--bg); border-radius:0 6px 6px 0; margin-bottom:10px; font-size:0.9rem; }
    .event-time { font-size:0.75rem; color:var(--muted); font-weight:600; }
    
    .diagnostics { font-family:monospace; font-size:0.8rem; color:var(--muted); margin-top:16px; padding:12px; background:var(--bg); border-radius:6px; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>User Dashboard</h1>
      <form method="post" action="/logout"><button class="btn-logout" type="submit">Logout</button></form>
    </header>

    <div class="grid">
      <div class="card">
        <div class="cal-header">
          <h2 id="month-year">Calendar</h2>
          <div style="display:flex;gap:8px">
            <button class="btn-logout" onclick="prevMonth()">←</button>
            <button class="btn-logout" onclick="nextMonth()">→</button>
          </div>
        </div>
        <div class="cal-grid" id="calendar"></div>
        
        <div class="event-list">
          <h2 id="selected-date-label">Schedule</h2>
          <div id="events-container">
            <div class="event-item"><div class="event-time">09:00 AM</div><div>Standard Maintenance - Strand</div></div>
            <div class="event-item"><div class="event-time">02:30 PM</div><div>Site Visit: Solar Quote - Somerset West</div></div>
          </div>
        </div>
      </div>

      <div class="card">
        <h2>Performance</h2>
        <div id="diag-summary">Loading...</div>
        <div class="diagnostics" id="runtime"></div>
        
        <h2 style="margin-top:24px">Recent Activity</h2>
        <div id="activity-list" style="font-size:0.85rem"></div>
      </div>
    </div>
  </div>

  <script>
    let currentDate = new Date();
    const events = {
      [new Date().toISOString().split('T')[0]]: [
        { time: '09:00 AM', title: 'Standard Maintenance - Strand' },
        { time: '02:30 PM', title: 'Site Visit: Solar Quote - Somerset West' }
      ]
    };

    function renderCalendar() {
      const cal = document.getElementById('calendar');
      const label = document.getElementById('month-year');
      cal.innerHTML = '';
      
      const year = currentDate.getFullYear();
      const month = currentDate.getMonth();
      label.innerText = new Intl.DateTimeFormat('en-US', { month: 'long', year: 'numeric' }).format(currentDate);
      
      ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].forEach(d => cal.innerHTML += `<div class="cal-day-label">${d}</div>`);
      
      const firstDay = new Date(year, month, 1).getDay();
      const daysInMonth = new Date(year, month + 1, 0).getDate();
      const today = new Date();
      
      for(let i=0; i<firstDay; i++) cal.innerHTML += '<div></div>';
      
      for(let d=1; d<=daysInMonth; d++) {
        const dateStr = `${year}-${String(month+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
        const isToday = today.getFullYear() === year && today.getMonth() === month && today.getDate() === d;
        const hasEvent = !!events[dateStr];
        
        const dayEl = document.createElement('div');
        dayEl.className = `cal-day ${isToday ? 'today' : ''} ${hasEvent ? 'has-event' : ''}`;
        dayEl.innerText = d;
        dayEl.onclick = () => selectDate(dateStr);
        cal.appendChild(dayEl);
      }
    }

    function selectDate(dateStr) {
      document.getElementById('selected-date-label').innerText = 'Schedule for ' + dateStr;
      const container = document.getElementById('events-container');
      const dayEvents = events[dateStr] || [];
      container.innerHTML = dayEvents.map(e => 
        `<div class="event-item"><div class="event-time">${e.time}</div><div>${e.title}</div></div>`
      ).join('') || '<div class="empty">No tasks scheduled.</div>';
    }

    function prevMonth() { currentDate.setMonth(currentDate.getMonth() - 1); renderCalendar(); }
    function nextMonth() { currentDate.setMonth(currentDate.getMonth() + 1); renderCalendar(); }

    async function load() {
      try {
        const data = await fetch('/api/user/diagnostics').then(r => r.json());
        document.getElementById('diag-summary').innerHTML = `
          <div style="margin-bottom:8px"><strong>Total Requests:</strong> ${data.totalRequests}</div>
          <div style="font-size:0.9rem; color:var(--muted)">Average response times look stable.</div>
        `;
        document.getElementById('runtime').innerText = `OS: ${data.os} | .NET: ${data.dotnet} | Machine: ${data.machine}`;
        document.getElementById('activity-list').innerHTML = data.recentStatuses.map(s => 
          `<div style="padding:6px 0; border-bottom:1px solid var(--border)">${s}</div>`
        ).join('') || 'No activity yet.';
      } catch (e) { console.error(e); }
    }

    renderCalendar();
    load();
    setInterval(load, 10000);
  </script>
</body>
</html>
""";
}
