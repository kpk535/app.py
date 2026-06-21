namespace WebBrowser.Engine;

public class HttpEngine
{
    private readonly HttpClient _httpClient;
    private const string UserAgent = "WebBrowser/1.0 (Windows NT 10.0; Win64; x64) Custom Engine";

    public HttpEngine()
    {
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = new System.Net.CookieContainer(),
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5
        };
        _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        _httpClient.DefaultRequestHeaders.Add("User-Agent", UserAgent);
        _httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
        _httpClient.DefaultRequestHeaders.Add("Accept-Encoding", "gzip, deflate");
    }

    public async Task<WebPage> FetchPageAsync(string url)
    {
        var page = new WebPage { Url = url };
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            if (!url.StartsWith("http://") && !url.StartsWith("https://"))
                url = "http://" + url;

            var response = await _httpClient.GetAsync(url);
            page.StatusCode = (int)response.StatusCode;

            foreach (var header in response.Headers)
                page.Headers[header.Key] = string.Join(", ", header.Value);

            var html = await response.Content.ReadAsStringAsync();
            page.Html = html;

            ParseHtmlContent(page, html);
            stopwatch.Stop();
            page.LoadTimeMs = stopwatch.ElapsedMilliseconds;

            return page;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            page.LoadTimeMs = stopwatch.ElapsedMilliseconds;
            page.PlainText = $"Error loading page: {ex.Message}";
            page.StatusCode = 0;
            return page;
        }
    }

    private void ParseHtmlContent(WebPage page, string html)
    {
        try
        {
            var doc = new HtmlAgilityPack.HtmlDocument();
            doc.LoadHtml(html);

            var titleNode = doc.DocumentNode.SelectSingleNode("//title");
            page.Title = titleNode?.InnerText ?? "Untitled";

            ExtractLinks(page, doc);
            ExtractPlainText(page, doc);
        }
        catch
        {
            page.PlainText = html;
        }
    }

    private void ExtractLinks(WebPage page, HtmlAgilityPack.HtmlDocument doc)
    {
        var linkNodes = doc.DocumentNode.SelectNodes("//a[@href]");
        if (linkNodes == null) return;

        foreach (var node in linkNodes)
        {
            var href = node.GetAttributeValue("href", "").Trim();
            if (string.IsNullOrWhiteSpace(href)) continue;

            var link = new WebLink
            {
                Href = href,
                Text = HtmlAgilityPack.HtmlEntity.DeEntitize(node.InnerText).Trim(),
                Title = node.GetAttributeValue("title", "")
            };

            if (!string.IsNullOrEmpty(link.Href))
                page.Links.Add(link);
        }
    }

    private void ExtractPlainText(WebPage page, HtmlAgilityPack.HtmlDocument doc)
    {
        var textNodes = doc.DocumentNode.SelectNodes("//text()");
        if (textNodes == null) return;

        var text = string.Join(" ", textNodes
            .Select(n => HtmlAgilityPack.HtmlEntity.DeEntitize(n.InnerText).Trim())
            .Where(t => !string.IsNullOrEmpty(t)));

        page.PlainText = System.Text.RegularExpressions.Regex.Replace(text, @"\s+", " ");
    }
}
