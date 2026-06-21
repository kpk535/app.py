namespace WebBrowser.Game;

public class LocalGameServer
{
    private readonly GameEngine _gameEngine = new();
    private readonly Dictionary<string, string> _sessionCookies = new();

    public string HandleRequest(string path, Dictionary<string, string>? queryParams = null, Dictionary<string, string>? postData = null)
    {
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        return segments.FirstOrDefault() switch
        {
            "game" when segments.Length > 1 => HandleGameRequest(segments[1], queryParams, postData),
            "api" when segments.Length > 1 => HandleApiRequest(segments[1], queryParams, postData),
            _ => ""
        };
    }

    private string HandleGameRequest(string action, Dictionary<string, string>? query, Dictionary<string, string>? post)
    {
        return action switch
        {
            "login" => _gameEngine.RenderLoginPage(),
            "logout" => HandleLogout(query),
            "next" => HandleNextLevel(query),
            _ => _gameEngine.RenderLoginPage()
        };
    }

    private string HandleApiRequest(string action, Dictionary<string, string>? query, Dictionary<string, string>? post)
    {
        return action switch
        {
            "login" => HandleLogin(post),
            _ => ""
        };
    }

    private string HandleLogin(Dictionary<string, string>? data)
    {
        if (data == null || !data.ContainsKey("username") || !data.ContainsKey("password"))
            return _gameEngine.RenderLoginPage();

        var username = data["username"];
        var password = data["password"];
        var sessionId = _gameEngine.CreateSession(username, password);

        if (string.IsNullOrEmpty(sessionId))
        {
            return @"
<!DOCTYPE html>
<html>
<head><title>Login Failed</title></head>
<body>
    <h1>Invalid Credentials</h1>
    <p><a href=""/game/login"">Try again</a></p>
</body>
</html>";
        }

        _sessionCookies["GAME_SESSION"] = sessionId;
        var session = _gameEngine.GetSession(sessionId);

        return session?.Role == "admin"
            ? _gameEngine.RenderAdminPage(sessionId)
            : _gameEngine.RenderUserPage(sessionId);
    }

    private string HandleLogout(Dictionary<string, string>? query)
    {
        if (query?.TryGetValue("session", out var sessionId) == true)
            _gameEngine.DestroySession(sessionId);

        _sessionCookies.Clear();
        return _gameEngine.RenderLoginPage();
    }

    private string HandleNextLevel(Dictionary<string, string>? query)
    {
        if (!query?.TryGetValue("session", out var sessionId) == true)
            return _gameEngine.RenderLoginPage();

        var session = _gameEngine.GetSession(sessionId);
        if (session == null) return _gameEngine.RenderLoginPage();

        if (session.CurrentLevel < 20)
        {
            session.CurrentLevel++;
        }

        return _gameEngine.RenderUserPage(sessionId);
    }

    public string GetCurrentSessionId() => _sessionCookies.TryGetValue("GAME_SESSION", out var id) ? id : "";
}
