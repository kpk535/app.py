using Bogus;

namespace WebBrowser.Game;

public class GameSession
{
    public string Id { get; } = Guid.NewGuid().ToString("N");
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = "user";
    public int CurrentLevel { get; set; } = 1;
    public bool IsAuthenticated { get; set; }
    public DateTime LoginTime { get; set; } = DateTime.UtcNow;
    public List<int> CompletedLevels { get; } = new();
}

public class GameEngine
{
    private readonly Dictionary<string, GameSession> _sessions = new();
    private readonly List<(string Username, string Password)> _levelCreds = new();
    private readonly Faker _faker = new();

    private readonly string[] _hints =
    [
        "Try SQL Injection: enter <code>' OR '1'='1</code> as the username.",
        "Password bypass: use <code>' OR '1'='1'--</code> in the password field.",
        "Look for a reflected XSS flaw in the search parameter.",
        "Try injecting <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> in the name field.",
        "Use multi-parameter SQL Injection across username AND email fields.",
        "Try a UNION-based SQL Injection to extract the users table.",
        "The page reflects data from a cookie — try XSS via cookie injection.",
        "Attempt a DOM-based XSS via the <code>hash</code> fragment of the URL.",
        "The session cookie has no <code>HttpOnly</code> flag. Can you steal it?",
        "Try path traversal: <code>../../etc/passwd</code> in the file parameter.",
        "Use UNION SELECT to enumerate the database schema.",
        "Try time-based blind SQLi: <code>' OR SLEEP(3)--</code>.",
        "The XSS filter blocks script tags — try <code>&lt;img onerror=alert(1)&gt;</code>.",
        "The form lacks a CSRF token. Craft a request from another origin.",
        "LFI: use <code>?file=../../../../etc/hosts</code> to read system files.",
        "RFI: provide an external URL as the file parameter.",
        "The password check can be bypassed — try logging in as <code>admin'--</code>.",
        "The MFA code is predictable (timestamp-based). Can you compute the next one?",
        "The file upload doesn't validate extensions — try a .php disguised as .jpg.",
        "Chained exploit: combine SSRF + RCE to execute commands on the server."
    ];

    public GameEngine()
    {
        for (int i = 0; i < 20; i++)
            _levelCreds.Add((_faker.Internet.UserName(), _faker.Internet.Password(8)));
    }

    public string CreateSession(string username, string password)
    {
        if (username == "admin" && password == "adminpass")
        {
            var s = new GameSession { Username = username, Role = "admin", IsAuthenticated = true };
            _sessions[s.Id] = s;
            return s.Id;
        }

        for (int i = 0; i < _levelCreds.Count; i++)
        {
            if (_levelCreds[i].Username == username && _levelCreds[i].Password == password)
            {
                var s = new GameSession { Username = username, Role = "user", CurrentLevel = i + 1, IsAuthenticated = true };
                _sessions[s.Id] = s;
                return s.Id;
            }
        }

        return string.Empty;
    }

    public GameSession? GetSession(string id) =>
        _sessions.TryGetValue(id, out var s) ? s : null;

    public void DestroySession(string id) => _sessions.Remove(id);

    public string GetHint(int level) =>
        level >= 1 && level <= _hints.Length ? _hints[level - 1] : "No hint available for this level.";

    public string RenderLoginPage(string? error = null) => $@"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>Hacking Game — Login</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif;
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
          min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
  .card {{ background: rgba(255,255,255,0.05); backdrop-filter: blur(20px);
           border: 1px solid rgba(255,255,255,0.1); border-radius: 20px;
           padding: 40px; width: 380px; box-shadow: 0 25px 50px rgba(0,0,0,0.5); }}
  .logo {{ text-align: center; font-size: 3em; margin-bottom: 8px; }}
  h1 {{ text-align: center; color: #e2e8f0; font-size: 1.5em; font-weight: 500; margin-bottom: 4px; }}
  .subtitle {{ text-align: center; color: #94a3b8; font-size: 0.85em; margin-bottom: 32px; }}
  label {{ display: block; color: #cbd5e1; font-size: 0.85em; font-weight: 500;
           margin-bottom: 6px; letter-spacing: 0.5px; }}
  input {{ width: 100%; background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.12);
           border-radius: 10px; padding: 12px 16px; color: #e2e8f0; font-size: 0.95em;
           outline: none; transition: border 0.2s; margin-bottom: 18px; }}
  input:focus {{ border-color: #667eea; background: rgba(255,255,255,0.12); }}
  button {{ width: 100%; background: linear-gradient(135deg, #667eea, #764ba2);
            border: none; border-radius: 10px; padding: 13px; color: white;
            font-size: 1em; font-weight: 600; cursor: pointer; margin-top: 8px;
            transition: opacity 0.2s; letter-spacing: 0.5px; }}
  button:hover {{ opacity: 0.88; }}
  .hint {{ background: rgba(102,126,234,0.15); border: 1px solid rgba(102,126,234,0.3);
           border-radius: 8px; padding: 10px 14px; margin-top: 20px;
           color: #a5b4fc; font-size: 0.8em; text-align: center; }}
  .error {{ background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.3);
            border-radius: 8px; padding: 10px 14px; margin-bottom: 20px;
            color: #fca5a5; font-size: 0.85em; text-align: center; }}
  .divider {{ text-align: center; color: #475569; font-size: 0.8em; margin: 16px 0; }}
</style>
</head>
<body>
  <div class='card'>
    <div class='logo'>🕵️</div>
    <h1>Hacking Challenge</h1>
    <p class='subtitle'>20 levels of security vulnerabilities</p>

    {(error != null ? $"<div class='error'>⚠ {System.Net.WebUtility.HtmlEncode(error)}</div>" : "")}

    <form method='POST' action='/game/login'>
      <label>Username</label>
      <input type='text' name='username' placeholder='Enter username' autocomplete='off'>
      <label>Password</label>
      <input type='password' name='password' placeholder='Enter password'>
      <button type='submit'>→ Login</button>
    </form>

    <div class='hint'>
      💡 Admin credentials: <strong>admin</strong> / <strong>adminpass</strong>
    </div>
  </div>
</body>
</html>";

    public string RenderAdminPage(GameSession session) => $@"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>Admin Panel</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f0f1a; color: #e2e8f0; min-height: 100vh; }}
  .topbar {{ background: linear-gradient(135deg, #667eea, #764ba2); padding: 20px 40px;
             display: flex; align-items: center; justify-content: space-between; }}
  .topbar h1 {{ font-size: 1.3em; font-weight: 600; }}
  .logout {{ color: rgba(255,255,255,0.8); text-decoration: none; font-size: 0.85em;
             background: rgba(255,255,255,0.15); padding: 6px 14px; border-radius: 20px; }}
  .content {{ max-width: 900px; margin: 40px auto; padding: 0 20px; }}
  .welcome {{ background: rgba(102,126,234,0.1); border: 1px solid rgba(102,126,234,0.2);
              border-radius: 12px; padding: 24px; margin-bottom: 30px; }}
  .welcome h2 {{ font-size: 1.2em; margin-bottom: 8px; color: #a5b4fc; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 30px; }}
  .stat {{ background: rgba(255,255,255,0.05); border-radius: 12px; padding: 20px; text-align: center; }}
  .stat-num {{ font-size: 2.5em; font-weight: 700; color: #667eea; }}
  .stat-label {{ font-size: 0.8em; color: #94a3b8; margin-top: 4px; }}
  .levels {{ background: rgba(255,255,255,0.03); border-radius: 12px; padding: 24px; }}
  .levels h3 {{ color: #94a3b8; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }}
  .level-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }}
  .level-btn {{ background: rgba(102,126,234,0.15); border: 1px solid rgba(102,126,234,0.3);
                border-radius: 8px; padding: 12px; text-align: center; cursor: pointer; }}
  .level-btn a {{ color: #a5b4fc; text-decoration: none; font-size: 0.85em; font-weight: 500; }}
  .level-btn:hover {{ background: rgba(102,126,234,0.3); }}
</style>
</head>
<body>
  <div class='topbar'>
    <h1>🔐 Admin Panel</h1>
    <a class='logout' href='/game/logout?session={session.Id}'>Logout</a>
  </div>
  <div class='content'>
    <div class='welcome'>
      <h2>Welcome back, {System.Net.WebUtility.HtmlEncode(session.Username)}!</h2>
      <p style='color:#94a3b8;font-size:0.9em;'>You have administrator access. You can view all challenge levels and user sessions.</p>
    </div>
    <div class='stat-grid'>
      <div class='stat'>
        <div class='stat-num'>20</div>
        <div class='stat-label'>Total Levels</div>
      </div>
      <div class='stat'>
        <div class='stat-num'>{_sessions.Count}</div>
        <div class='stat-label'>Active Sessions</div>
      </div>
      <div class='stat'>
        <div class='stat-num'>8</div>
        <div class='stat-label'>Vuln Categories</div>
      </div>
    </div>
    <div class='levels'>
      <h3>Challenge Levels</h3>
      <div class='level-grid'>
        {string.Join("", Enumerable.Range(1, 20).Select(i =>
            $"<div class='level-btn'><a href='/game/level?n={i}&session={session.Id}'>Level {i}</a></div>"))}
      </div>
    </div>
  </div>
</body>
</html>";

    public string RenderUserPage(GameSession session)
    {
        var hint = GetHint(session.CurrentLevel);
        var progress = (double)session.CurrentLevel / 20 * 100;

        return $@"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>Level {session.CurrentLevel} — Hacking Challenge</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f0f1a; color: #e2e8f0; min-height: 100vh; }}
  .topbar {{ background: rgba(255,255,255,0.04); border-bottom: 1px solid rgba(255,255,255,0.08);
             padding: 16px 40px; display: flex; align-items: center; justify-content: space-between; }}
  .level-badge {{ background: linear-gradient(135deg, #667eea, #764ba2);
                  padding: 6px 16px; border-radius: 20px; font-size: 0.85em; font-weight: 600; }}
  .logout {{ color: #94a3b8; text-decoration: none; font-size: 0.85em; }}
  .progress-bar {{ width: 100%; height: 3px; background: rgba(255,255,255,0.08); }}
  .progress-fill {{ height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); width: {progress}%; transition: width 0.6s; }}
  .content {{ max-width: 760px; margin: 48px auto; padding: 0 20px; }}
  .card {{ background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08);
           border-radius: 16px; padding: 36px; margin-bottom: 24px; }}
  .card h1 {{ font-size: 1.6em; color: #a5b4fc; margin-bottom: 6px; }}
  .user-info {{ color: #64748b; font-size: 0.85em; margin-bottom: 24px; }}
  .hint-box {{ background: rgba(234,179,8,0.08); border: 1px solid rgba(234,179,8,0.2);
               border-radius: 12px; padding: 20px 24px; margin-bottom: 24px; }}
  .hint-label {{ font-size: 0.75em; text-transform: uppercase; letter-spacing: 1.5px;
                 color: #fbbf24; margin-bottom: 8px; font-weight: 600; }}
  .hint-text {{ color: #fde68a; font-size: 0.95em; line-height: 1.7; }}
  .hint-text code {{ background: rgba(251,191,36,0.15); padding: 2px 8px; border-radius: 4px;
                     font-family: 'Consolas', monospace; font-size: 0.9em; }}
  .actions {{ display: flex; gap: 12px; }}
  .btn {{ padding: 12px 24px; border-radius: 10px; font-size: 0.9em; font-weight: 600;
          text-decoration: none; cursor: pointer; letter-spacing: 0.3px; border: none; }}
  .btn-primary {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; }}
  .btn-ghost {{ background: rgba(255,255,255,0.07); border: 1px solid rgba(255,255,255,0.1); color: #94a3b8; }}
  .level-map {{ display: flex; gap: 4px; flex-wrap: wrap; }}
  .lm {{ width: 32px; height: 32px; border-radius: 6px; display: flex; align-items: center;
         justify-content: center; font-size: 0.75em; font-weight: 600;
         background: rgba(255,255,255,0.06); color: #64748b; }}
  .lm.current {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; }}
  .lm.done {{ background: rgba(34,197,94,0.2); color: #4ade80; }}
</style>
</head>
<body>
  <div class='topbar'>
    <div class='level-badge'>Level {session.CurrentLevel} of 20</div>
    <span style='color:#64748b;font-size:0.85em;'>Logged in as <strong style='color:#94a3b8'>{System.Net.WebUtility.HtmlEncode(session.Username)}</strong></span>
    <a class='logout' href='/game/logout?session={session.Id}'>Logout</a>
  </div>
  <div class='progress-bar'><div class='progress-fill'></div></div>

  <div class='content'>
    <div class='card'>
      <h1>🎯 Level {session.CurrentLevel}</h1>
      <p class='user-info'>{GetLevelCategory(session.CurrentLevel)}</p>
      <div class='hint-box'>
        <div class='hint-label'>💡 Objective</div>
        <div class='hint-text'>{hint}</div>
      </div>
      <div class='actions'>
        <a class='btn btn-primary' href='/game/next?session={session.Id}'>Complete Level →</a>
        <a class='btn btn-ghost' href='/game/login'>← Back to Login</a>
      </div>
    </div>

    <div class='card' style='padding: 24px 36px;'>
      <p style='color:#64748b;font-size:0.8em;text-transform:uppercase;letter-spacing:1px;margin-bottom:14px;'>Progress</p>
      <div class='level-map'>
        {string.Join("", Enumerable.Range(1, 20).Select(i =>
            $"<div class='lm {(i == session.CurrentLevel ? "current" : i < session.CurrentLevel ? "done" : "")}'>{i}</div>"))}
      </div>
    </div>
  </div>
</body>
</html>";
    }

    private static string GetLevelCategory(int level) => level switch
    {
        1 or 2 => "SQL Injection — Basics",
        3 or 4 => "Cross-Site Scripting (XSS) — Reflected",
        5 or 6 => "SQL Injection — Advanced",
        7 or 8 => "XSS — DOM & Stored",
        9 => "Authentication Bypass",
        10 => "Path Traversal",
        11 or 12 => "SQL Injection — Blind & UNION",
        13 => "XSS — Filter Evasion",
        14 => "CSRF",
        15 or 16 => "File Inclusion (LFI/RFI)",
        17 or 18 => "Authentication — MFA Bypass",
        19 => "Remote Code Execution",
        20 => "Chained Exploit",
        _ => "Unknown"
    };
}
