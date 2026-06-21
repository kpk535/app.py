using WebBrowser.Game;

namespace WebBrowser.Engine;

public class ProtocolHandler
{
    private readonly HttpEngine _httpEngine;
    private readonly LocalGameServer _gameServer = new();

    public ProtocolHandler(HttpEngine httpEngine)
    {
        _httpEngine = httpEngine;
    }

    public async Task<WebPage> FetchAsync(string url)
    {
        if (url.StartsWith("game://localhost"))
        {
            return HandleGameProtocol(url);
        }

        if (url.StartsWith("about:"))
        {
            return HandleAboutProtocol(url);
        }

        return await _httpEngine.FetchPageAsync(url);
    }

    private WebPage HandleGameProtocol(string url)
    {
        var uri = new Uri(url);
        var path = uri.PathAndQuery;
        var queryParams = ParseQuery(uri.Query);

        var html = _gameServer.HandleRequest(path, queryParams);

        return new WebPage
        {
            Url = url,
            Title = "Game",
            Html = html,
            StatusCode = 200,
            LoadTimeMs = 10
        };
    }

    private WebPage HandleAboutProtocol(string url)
    {
        return url switch
        {
            "about:home" => new WebPage
            {
                Url = url,
                Title = "Home",
                Html = LoadAboutHtml("home"),
                StatusCode = 200
            },
            "about:blank" => new WebPage
            {
                Url = url,
                Title = "Blank",
                Html = "<!DOCTYPE html><html><body></body></html>",
                StatusCode = 200
            },
            _ => new WebPage
            {
                Url = url,
                Title = "About",
                Html = "<!DOCTYPE html><html><body><h1>Unknown page</h1></body></html>",
                StatusCode = 404
            }
        };
    }

    private string LoadAboutHtml(string page)
    {
        return page switch
        {
            "home" => @"
<!DOCTYPE html>
<html>
<head>
    <title>Web Browser - Home</title>
    <style>
        body { font-family: 'Segoe UI', Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #667eea; }
        h2 { color: #764ba2; margin-top: 30px; }
        p { color: #666; line-height: 1.6; }
        ul { color: #666; }
        a { color: #667eea; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .features { background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🌐 Welcome to Custom Web Browser</h1>
    <p>A modern web browser built entirely in C# with a custom HTML engine and WPF GUI.</p>

    <div class=""features"">
        <h2>✨ Features</h2>
        <ul>
            <li>Custom HTTP client with cookie management</li>
            <li>HTML parser and smart renderer</li>
            <li>Automatic link extraction</li>
            <li>Full browser history (Back/Forward)</li>
            <li>Beautiful and smooth WPF interface</li>
            <li>Built-in security challenge game</li>
            <li>Fast page loading and rendering</li>
        </ul>
    </div>

    <h2>🚀 Getting Started</h2>
    <p>Try these URLs:</p>
    <ul>
        <li><a href=""game://localhost/game/login"">Play Hacking Game</a></li>
        <li><a href=""https://example.com"">Visit example.com</a></li>
        <li><a href=""https://github.com"">Browse GitHub</a></li>
    </ul>

    <h2>🎮 Hacking Game</h2>
    <p>Test your security knowledge with 20 levels of increasing difficulty:</p>
    <ul>
        <li>SQL Injection (Levels 1-2, 5-6, 11-12)</li>
        <li>Cross-Site Scripting (Levels 3-4, 7-8, 13)</li>
        <li>Authentication Bypass (Levels 9, 17-18)</li>
        <li>File Inclusion (Levels 10, 15-16)</li>
        <li>Code Execution (Levels 14, 19-20)</li>
    </ul>

    <h2>🔧 Custom Web Engine</h2>
    <p>This browser features:</p>
    <ul>
        <li><strong>Protocol Handling:</strong> Support for game://, about://, http://, https://</li>
        <li><strong>HTML Rendering:</strong> Clean rendering of semantic HTML</li>
        <li><strong>Link Management:</strong> Automatic extraction and navigation</li>
        <li><strong>Session Management:</strong> Cookie and session persistence</li>
    </ul>

    <p style=""margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; color: #999; font-size: 12px;"">
        Built with ❤️ using C# and WPF | Custom Web Engine v1.0
    </p>
</body>
</html>",
            _ => ""
        };
    }

    private Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>();
        if (string.IsNullOrEmpty(query) || query == "?") return result;

        foreach (var param in query.TrimStart('?').Split('&'))
        {
            var parts = param.Split('=', 2);
            if (parts.Length == 2)
                result[System.Net.WebUtility.UrlDecode(parts[0])] = System.Net.WebUtility.UrlDecode(parts[1]);
        }

        return result;
    }
}
