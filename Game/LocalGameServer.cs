using System;
using System.Collections.Generic;
using System.Linq;

namespace WebBrowser.Game;

public class LocalGameServer
{
    private readonly GameEngine _engine = new();

    public string HandleRequest(string path, Dictionary<string, string>? query = null, Dictionary<string, string>? post = null)
    {
        query ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        post ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0) return _engine.RenderLoginPage();

        return segments[0].ToLower() switch
        {
            "game" => HandleGame(segments.Length > 1 ? segments[1] : "login", query, post),
            _ => _engine.RenderLoginPage()
        };
    }

    private string HandleGame(string action, Dictionary<string, string> query, Dictionary<string, string> post)
    {
        return action.ToLower() switch
        {
            "login" when post.Count > 0 => HandleLogin(post),
            "login" => _engine.RenderLoginPage(),
            "logout" => HandleLogout(query),
            "next" => HandleNext(query),
            "level" => HandleLevel(query),
            _ => _engine.RenderLoginPage()
        };
    }

    private string HandleLogin(Dictionary<string, string> post)
    {
        var username = post.GetValueOrDefault("username", "").Trim();
        var password = post.GetValueOrDefault("password", "").Trim();

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return _engine.RenderLoginPage("Please enter both username and password.");

        var sessionId = _engine.CreateSession(username, password);
        if (string.IsNullOrEmpty(sessionId))
            return _engine.RenderLoginPage("Invalid credentials. Try again.");

        var session = _engine.GetSession(sessionId)!;
        return session.Role == "admin"
            ? _engine.RenderAdminPage(session)
            : _engine.RenderUserPage(session);
    }

    private string HandleLogout(Dictionary<string, string> query)
    {
        if (query.TryGetValue("session", out var id))
            _engine.DestroySession(id);
        return _engine.RenderLoginPage();
    }

    private string HandleNext(Dictionary<string, string> query)
    {
        if (!query.TryGetValue("session", out var id)) return _engine.RenderLoginPage();
        var session = _engine.GetSession(id);
        if (session == null) return _engine.RenderLoginPage("Session expired. Please log in again.");

        if (session.CurrentLevel < 20)
        {
            session.CompletedLevels.Add(session.CurrentLevel);
            session.CurrentLevel++;
        }
        else
        {
            return RenderVictoryPage(session);
        }

        return _engine.RenderUserPage(session);
    }

    private string HandleLevel(Dictionary<string, string> query)
    {
        if (!query.TryGetValue("session", out var id)) return _engine.RenderLoginPage();
        var session = _engine.GetSession(id);
        if (session == null) return _engine.RenderLoginPage("Session expired.");

        if (query.TryGetValue("n", out var nStr) && int.TryParse(nStr, out var n) && n >= 1 && n <= 20)
            session.CurrentLevel = n;

        return _engine.RenderUserPage(session);
    }

    private static string RenderVictoryPage(GameSession session) => $@"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>🏆 Challenge Complete!</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg,#0f0c29,#302b63,#24243e);
          min-height: 100vh; display: flex; align-items: center; justify-content: center; color: white; }}
  .card {{ text-align: center; padding: 60px 40px; max-width: 520px; }}
  .trophy {{ font-size: 5em; margin-bottom: 20px; animation: bounce 1s infinite alternate; }}
  @keyframes bounce {{ from {{ transform: translateY(0); }} to {{ transform: translateY(-20px); }} }}
  h1 {{ font-size: 2em; margin-bottom: 12px; background: linear-gradient(135deg,#ffd700,#ffb347);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  p {{ color: rgba(255,255,255,0.7); line-height: 1.8; margin-bottom: 8px; }}
  .stars {{ font-size: 2em; letter-spacing: 8px; margin: 20px 0; }}
  .btn {{ display: inline-block; margin-top: 28px; background: linear-gradient(135deg, #667eea, #764ba2);
          padding: 14px 32px; border-radius: 12px; text-decoration: none; color: white; font-weight: 600; }}
</style>
</head>
<body>
  <div class='card'>
    <div class='trophy'>🏆</div>
    <h1>Challenge Complete!</h1>
    <div class='stars'>⭐⭐⭐⭐⭐</div>
    <p>Congratulations, <strong>{System.Net.WebUtility.HtmlEncode(session.Username)}</strong>!</p>
    <p>You have successfully completed all 20 levels of the hacking challenge.</p>
    <p>You demonstrated mastery of SQL Injection, XSS, Auth Bypass, RCE, and more.</p>
    <a class='btn' href='/game/login'>Play Again →</a>
  </div>
</body>
</html>";
}
