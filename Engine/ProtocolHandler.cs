using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WebBrowser.Game;

namespace WebBrowser.Engine;

public class ProtocolHandler
{
    private readonly HttpEngine _httpEngine;
    private readonly LocalGameServer _gameServer = new();
    private readonly PageCache _cache = new();

    public event EventHandler<string>? StatusChanged;

    public ProtocolHandler(HttpEngine httpEngine)
    {
        _httpEngine = httpEngine;
        _httpEngine.StatusChanged += (s, e) => StatusChanged?.Invoke(s, e);
    }

    public async Task<WebPage> FetchAsync(string url, bool bypassCache = false, CancellationToken cancellationToken = default)
    {
        url = url.Trim();
        if (string.IsNullOrEmpty(url)) url = "about:home";

        // Check cache for HTTP pages
        if (!bypassCache && (url.StartsWith("http://") || url.StartsWith("https://")))
        {
            var cached = _cache.Get(url);
            if (cached != null)
            {
                StatusChanged?.Invoke(this, "Loaded from cache");
                return cached;
            }
        }

        WebPage page;

        if (url.StartsWith("about:"))
            page = HandleAbout(url);
        else if (url.StartsWith("game://"))
            page = HandleGame(url);
        else if (url.StartsWith("view-source:"))
            page = await HandleViewSource(url, cancellationToken);
        else if (url.StartsWith("file://"))
            page = HandleFile(url);
        else if (url.StartsWith("data:"))
            page = HandleData(url);
        else if (url.StartsWith("http://") || url.StartsWith("https://"))
        {
            page = await _httpEngine.FetchPageAsync(url, cancellationToken);
            if (!page.HasError)
                _cache.Put(url, page);
        }
        else
        {
            // Unknown protocol — try https
            page = await _httpEngine.FetchPageAsync("https://" + url, cancellationToken);
        }

        return page;
    }

    private WebPage HandleAbout(string url)
    {
        var path = url.Length > 6 ? url[6..] : "home";
        return path switch
        {
            "home" or "" => MakePage(url, "Home", BuildHomePage()),
            "blank" => MakePage(url, "Blank", "<!DOCTYPE html><html><body></body></html>"),
            "history" => MakePage(url, "History", BuildPlaceholderPage("History", "Your browsing history will appear here.")),
            "bookmarks" => MakePage(url, "Bookmarks", BuildPlaceholderPage("Bookmarks", "Your bookmarks will appear here.")),
            "settings" => MakePage(url, "Settings", BuildSettingsPage()),
            "cache" => MakePage(url, "Cache Info", BuildCachePage()),
            _ => MakePage(url, "Not Found", BuildPlaceholderPage("Page Not Found", $"No built-in page for: about:{path}"), 404)
        };
    }

    private WebPage HandleGame(string url)
    {
        try
        {
            var uri = new Uri(url);
            var path = uri.AbsolutePath;
            var query = ParseQuery(uri.Query);
            var sw = System.Diagnostics.Stopwatch.StartNew();

            var html = _gameServer.HandleRequest(path, query);
            sw.Stop();

            var page = new WebPage
            {
                Url = url,
                FinalUrl = url,
                Title = "Hacking Game",
                Html = html,
                StatusCode = 200,
                LoadTimeMs = sw.ElapsedMilliseconds
            };
            DomReader.EnrichPage(page);
            return page;
        }
        catch (Exception ex)
        {
            return MakePage(url, "Game Error", BuildPlaceholderPage("Game Error", ex.Message), 500);
        }
    }

    private async Task<WebPage> HandleViewSource(string url, CancellationToken ct)
    {
        var targetUrl = url["view-source:".Length..];
        var page = await _httpEngine.FetchSourceAsync(targetUrl, ct);
        page.Title = $"Source: {page.Title}";
        return page;
    }

    private WebPage HandleFile(string url)
    {
        try
        {
            var path = new Uri(url).LocalPath;
            if (!System.IO.File.Exists(path))
                return MakePage(url, "Not Found", BuildPlaceholderPage("File Not Found", path), 404);

            var ext = System.IO.Path.GetExtension(path).ToLower();
            var content = System.IO.File.ReadAllText(path, Encoding.UTF8);
            var mime = ext switch
            {
                ".html" or ".htm" => "text/html",
                ".json" => "application/json",
                ".xml" => "text/xml",
                ".txt" or ".md" => "text/plain",
                ".cs" or ".js" or ".py" or ".ts" => "text/plain",
                _ => "application/octet-stream"
            };

            var type = ContentTypeHandler.DetectContentType(mime, url, content);
            var html = type == ContentType.Html ? content : ContentTypeHandler.ConvertToHtml(content, type, url);

            var page = new WebPage
            {
                Url = url, FinalUrl = url,
                Html = html, RawContent = content,
                ContentType = type, StatusCode = 200,
                Title = System.IO.Path.GetFileName(path)
            };
            if (type == ContentType.Html) DomReader.EnrichPage(page);
            return page;
        }
        catch (Exception ex)
        {
            return MakePage(url, "File Error", BuildPlaceholderPage("File Error", ex.Message), 500);
        }
    }

    private WebPage HandleData(string url)
    {
        try
        {
            // data:[<mediatype>][;base64],<data>
            var rest = url[5..];
            var comma = rest.IndexOf(',');
            if (comma < 0) throw new Exception("Invalid data URI");

            var meta = rest[..comma];
            var dataStr = rest[(comma + 1)..];
            var isBase64 = meta.EndsWith(";base64");
            var mimeType = isBase64 ? meta[..^7] : meta;
            if (string.IsNullOrEmpty(mimeType)) mimeType = "text/plain";

            string content;
            if (isBase64)
                content = Encoding.UTF8.GetString(Convert.FromBase64String(dataStr));
            else
                content = Uri.UnescapeDataString(dataStr);

            var type = ContentTypeHandler.DetectContentType(mimeType, url, content);
            var html = type == ContentType.Html ? content : ContentTypeHandler.ConvertToHtml(content, type, url);

            return MakePage(url, "Data URI", html);
        }
        catch (Exception ex)
        {
            return MakePage(url, "Data Error", BuildPlaceholderPage("Data URI Error", ex.Message), 400);
        }
    }

    private static WebPage MakePage(string url, string title, string html, int code = 200) =>
        new() { Url = url, FinalUrl = url, Title = title, Html = html, StatusCode = code };

    private string BuildCachePage()
    {
        return BuildPlaceholderPage("Cache", $"Pages in cache: {_cache.Count}");
    }

    private static string BuildHomePage() => @"
<!DOCTYPE html>
<html>
<head><meta charset='utf-8'><title>New Tab</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg,#667eea 0%,#764ba2 100%);
         min-height: 100vh; display: flex; flex-direction: column; align-items: center;
         justify-content: center; color: white; padding: 40px 20px; }
  h1 { font-size: 2.4em; font-weight: 300; letter-spacing: -0.5px; margin-bottom: 8px; text-shadow: 0 2px 8px rgba(0,0,0,0.2); }
  .subtitle { opacity: 0.8; margin-bottom: 40px; font-size: 1em; }
  .cards { display: flex; gap: 20px; flex-wrap: wrap; justify-content: center; max-width: 900px; margin-bottom: 40px; }
  .card { background: rgba(255,255,255,0.15); backdrop-filter: blur(10px); border-radius: 16px;
          padding: 24px; width: 180px; text-align: center; border: 1px solid rgba(255,255,255,0.2);
          cursor: pointer; transition: transform 0.2s, background 0.2s; }
  .card:hover { transform: translateY(-4px); background: rgba(255,255,255,0.25); }
  .card a { color: white; text-decoration: none; display: block; }
  .icon { font-size: 2.4em; margin-bottom: 12px; display: block; }
  .card-title { font-weight: 600; font-size: 0.95em; margin-bottom: 4px; }
  .card-sub { font-size: 0.8em; opacity: 0.7; }
  .section-title { font-size: 0.8em; letter-spacing: 2px; text-transform: uppercase;
                   opacity: 0.7; margin-bottom: 16px; }
  .shortcuts { display: flex; gap: 12px; flex-wrap: wrap; justify-content: center; max-width: 700px; }
  .shortcut { background: rgba(255,255,255,0.1); border-radius: 8px; padding: 8px 16px;
              font-size: 0.85em; border: 1px solid rgba(255,255,255,0.15); }
  .shortcut a { color: white; text-decoration: none; }
  .footer { margin-top: 48px; font-size: 0.75em; opacity: 0.5; }
</style>
</head>
<body>
  <h1>🌐 Custom Browser</h1>
  <p class='subtitle'>A C# browser with a custom web engine</p>

  <p class='section-title'>Quick Access</p>
  <div class='cards'>
    <div class='card'><a href='game://localhost/game/login'>
      <span class='icon'>🎮</span>
      <div class='card-title'>Hacking Game</div>
      <div class='card-sub'>20 security levels</div>
    </a></div>
    <div class='card'><a href='https://example.com'>
      <span class='icon'>🌍</span>
      <div class='card-title'>Example</div>
      <div class='card-sub'>example.com</div>
    </a></div>
    <div class='card'><a href='https://github.com'>
      <span class='icon'>🐙</span>
      <div class='card-title'>GitHub</div>
      <div class='card-sub'>Source code</div>
    </a></div>
    <div class='card'><a href='https://news.ycombinator.com'>
      <span class='icon'>📰</span>
      <div class='card-title'>Hacker News</div>
      <div class='card-sub'>Tech stories</div>
    </a></div>
    <div class='card'><a href='about:settings'>
      <span class='icon'>⚙</span>
      <div class='card-title'>Settings</div>
      <div class='card-sub'>Browser config</div>
    </a></div>
  </div>

  <p class='section-title'>Keyboard Shortcuts</p>
  <div class='shortcuts'>
    <div class='shortcut'>Ctrl+T — New Tab</div>
    <div class='shortcut'>Ctrl+W — Close Tab</div>
    <div class='shortcut'>Ctrl+F — Find</div>
    <div class='shortcut'>Ctrl+R — Refresh</div>
    <div class='shortcut'>Ctrl+D — Bookmark</div>
    <div class='shortcut'>Alt+← → History</div>
    <div class='shortcut'>Ctrl+U — View Source</div>
    <div class='shortcut'>F8 — Reader Mode</div>
    <div class='shortcut'>F9 — Dark Mode</div>
  </div>

  <div class='footer'>Custom Web Engine v2.0 · Built with C# and WPF</div>
</body>
</html>";

    private static string BuildSettingsPage() => @"
<!DOCTYPE html>
<html>
<head><title>Settings</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; color: #333; }
  h1 { color: #667eea; border-bottom: 2px solid #eee; padding-bottom: 12px; }
  .section { margin: 24px 0; }
  .section h2 { font-size: 1em; color: #555; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
  .item { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #f0f0f0; }
  .item-label { font-size: 0.95em; }
  .item-sub { font-size: 0.8em; color: #999; margin-top: 2px; }
  code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }
</style>
</head>
<body>
  <h1>⚙ Browser Settings</h1>

  <div class='section'>
    <h2>Search Engine</h2>
    <div class='item'>
      <div>
        <div class='item-label'>Default Search</div>
        <div class='item-sub'>DuckDuckGo (change via address bar bangs: !g, !bing, !wiki)</div>
      </div>
    </div>
  </div>

  <div class='section'>
    <h2>Shortcuts</h2>
    <div class='item'><div class='item-label'>New Tab</div><code>Ctrl+T</code></div>
    <div class='item'><div class='item-label'>Close Tab</div><code>Ctrl+W</code></div>
    <div class='item'><div class='item-label'>Find in Page</div><code>Ctrl+F</code></div>
    <div class='item'><div class='item-label'>View Source</div><code>Ctrl+U</code></div>
    <div class='item'><div class='item-label'>Reader Mode</div><code>F8</code></div>
    <div class='item'><div class='item-label'>Dark Mode</div><code>F9</code></div>
    <div class='item'><div class='item-label'>Bookmark</div><code>Ctrl+D</code></div>
    <div class='item'><div class='item-label'>Back / Forward</div><code>Alt+← / →</code></div>
  </div>

  <div class='section'>
    <h2>About</h2>
    <div class='item'><div class='item-label'>Browser</div><div>Custom Web Browser v2.0</div></div>
    <div class='item'><div class='item-label'>Engine</div><div>Custom HTML Engine (WPF FlowDocument)</div></div>
    <div class='item'><div class='item-label'>Runtime</div><div>.NET 8.0</div></div>
    <div class='item'><div class='item-label'>Parser</div><div>HtmlAgilityPack 1.11.61</div></div>
  </div>
</body>
</html>";

    private static string BuildPlaceholderPage(string title, string message) => $@"
<!DOCTYPE html>
<html>
<head><title>{System.Net.WebUtility.HtmlEncode(title)}</title></head>
<body>
  <h1>{System.Net.WebUtility.HtmlEncode(title)}</h1>
  <p>{System.Net.WebUtility.HtmlEncode(message)}</p>
</body>
</html>";

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(query) || query == "?") return result;
        foreach (var param in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = param.IndexOf('=');
            if (idx > 0)
                result[Uri.UnescapeDataString(param[..idx])] = Uri.UnescapeDataString(param[(idx + 1)..]);
        }
        return result;
    }
}
