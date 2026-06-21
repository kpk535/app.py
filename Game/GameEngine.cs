namespace WebBrowser.Game;

public class GameSession
{
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = "user";
    public int CurrentLevel { get; set; } = 0;
    public bool IsAuthenticated { get; set; } = false;
    public DateTime LoginTime { get; set; }
}

public class GameEngine
{
    private readonly Dictionary<string, GameSession> _sessions = new();
    private readonly Dictionary<string, string> _credentials = new() { { "admin", "adminpass" } };
    private readonly Random _random = new();

    private const string AdminCredential = "admin";
    private const string AdminPassword = "adminpass";

    private readonly string[] _hints = new[]
    {
        "Try basic SQL Injection with ' OR '1'='1",
        "Try adding ' OR '1'='1 to the password",
        "Look for XSS vulnerabilities in the search box.",
        "Try injecting a <script>alert('XSS')</script> tag.",
        "Find a way to inject SQL through multiple parameters.",
        "Try a more complex SQL Injection attack.",
        "Look for different vectors for XSS.",
        "Try DOM-based XSS attack vectors.",
        "Explore potential authentication bypass.",
        "Look for directory traversal vulnerabilities.",
        "Try advanced SQL Injection with union-based attack.",
        "Try time-based blind SQL Injection.",
        "Attempt to bypass advanced XSS filters.",
        "Exploit CSRF vulnerabilities in forms.",
        "Look for local file inclusion (LFI) vulnerabilities.",
        "Try remote file inclusion (RFI) attacks.",
        "Explore advanced authentication bypass techniques.",
        "Attempt to bypass multi-factor authentication.",
        "Look for remote code execution (RCE) vulnerabilities.",
        "Try to find zero-day vulnerabilities akin to Google security."
    };

    public GameEngine()
    {
        GenerateLevelCredentials();
    }

    private void GenerateLevelCredentials()
    {
        var faker = new Faker.Faker();
        for (int i = 0; i < 20; i++)
        {
            var username = faker.Internet.UserName();
            var password = GeneratePassword();
            _credentials[username] = password;
        }
    }

    private string GeneratePassword()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        return new string(Enumerable.Range(0, 8).Select(_ => chars[_random.Next(chars.Length)]).ToArray());
    }

    public string CreateSession(string username, string password)
    {
        if (username == AdminCredential && password == AdminPassword)
        {
            var sessionId = Guid.NewGuid().ToString();
            _sessions[sessionId] = new GameSession
            {
                Username = username,
                Role = "admin",
                IsAuthenticated = true,
                LoginTime = DateTime.UtcNow
            };
            return sessionId;
        }

        if (_credentials.TryGetValue(username, out var storedPassword) && storedPassword == password)
        {
            var sessionId = Guid.NewGuid().ToString();
            var level = _credentials.Keys.ToList().IndexOf(username) + 1;
            _sessions[sessionId] = new GameSession
            {
                Username = username,
                Role = "user",
                CurrentLevel = level,
                IsAuthenticated = true,
                LoginTime = DateTime.UtcNow
            };
            return sessionId;
        }

        return string.Empty;
    }

    public GameSession? GetSession(string sessionId)
    {
        return _sessions.TryGetValue(sessionId, out var session) ? session : null;
    }

    public void DestroySession(string sessionId)
    {
        _sessions.Remove(sessionId);
    }

    public string GetHint(int level)
    {
        return level > 0 && level <= _hints.Length ? _hints[level - 1] : "No hint available";
    }

    public string RenderLoginPage()
    {
        return @"
<!DOCTYPE html>
<html>
<head>
    <title>Hacking Game - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                     width: 300px; }
        h1 { color: #333; text-align: center; margin-top: 0; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { width: 100%; padding: 10px; margin-top: 20px; background: #667eea; color: white; border: none;
                 border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold; }
        button:hover { background: #764ba2; }
    </style>
</head>
<body>
    <div class=""login-box"">
        <h1>🎮 Hacking Game</h1>
        <form method=""POST"" action=""/api/login"">
            <input type=""text"" name=""username"" placeholder=""Username"" required>
            <input type=""password"" name=""password"" placeholder=""Password"" required>
            <button type=""submit"">Login</button>
        </form>
        <p style=""text-align: center; color: #888; margin-top: 20px;"">Admin: admin / adminpass</p>
    </div>
</body>
</html>";
    }

    public string RenderAdminPage(string sessionId)
    {
        var session = GetSession(sessionId);
        if (session == null) return "";

        return $@"
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body {{ font-family: Arial; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #667eea; }}
        .info {{ background: #e8f4f8; padding: 15px; border-left: 4px solid #667eea; margin: 20px 0; }}
        a {{ color: #667eea; text-decoration: none; margin-right: 15px; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class=""container"">
        <h1>🔒 Admin Panel</h1>
        <div class=""info"">
            <p><strong>Welcome, {session.Username}!</strong></p>
            <p>Your task is to find and fix vulnerabilities in the game system.</p>
        </div>
        <p><a href=""/game/logout"">Logout</a></p>
    </div>
</body>
</html>";
    }

    public string RenderUserPage(string sessionId)
    {
        var session = GetSession(sessionId);
        if (session == null) return "";

        var hint = GetHint(session.CurrentLevel);
        return $@"
<!DOCTYPE html>
<html>
<head>
    <title>Level {session.CurrentLevel}</title>
    <style>
        body {{ font-family: Arial; background: #f5f5f5; margin: 0; padding: 20px; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #667eea; }}
        .level-indicator {{ background: #667eea; color: white; padding: 10px 15px; border-radius: 5px; display: inline-block; margin: 10px 0; }}
        .hint {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; border-radius: 4px; }}
        .hint-title {{ font-weight: bold; color: #856404; }}
        a {{ color: #667eea; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class=""container"">
        <h1>🎯 Hacking Challenge</h1>
        <div class=""level-indicator"">Level {session.CurrentLevel} / 20</div>
        <p><strong>Welcome, {session.Username}!</strong></p>
        <div class=""hint"">
            <div class=""hint-title"">💡 Hint:</div>
            {hint}
        </div>
        <p><a href=""/game/next"">Next Level →</a> | <a href=""/game/logout"">Logout</a></p>
    </div>
</body>
</html>";
    }
}
