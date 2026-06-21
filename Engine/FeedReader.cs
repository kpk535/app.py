using System.Xml.Linq;

namespace WebBrowser.Engine;

public class FeedItem
{
    public string Title { get; set; } = string.Empty;
    public string Link { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public DateTime? Published { get; set; }
    public string Category { get; set; } = string.Empty;
}

public class Feed
{
    public string Title { get; set; } = string.Empty;
    public string Link { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string FeedType { get; set; } = string.Empty;
    public DateTime? Updated { get; set; }
    public List<FeedItem> Items { get; set; } = new();
}

public static class FeedReader
{
    public static bool IsFeed(string content, string contentType = "")
    {
        if (contentType.Contains("rss") || contentType.Contains("atom") || contentType.Contains("xml"))
            return true;

        var trimmed = content.TrimStart();
        return trimmed.Contains("<rss") || trimmed.Contains("<feed") || trimmed.Contains("<channel");
    }

    public static Feed? Parse(string content)
    {
        try
        {
            var xml = XDocument.Parse(content);
            var root = xml.Root;
            if (root == null) return null;

            return root.Name.LocalName.ToLower() switch
            {
                "rss" => ParseRss(root),
                "feed" => ParseAtom(root),
                _ when root.Element("channel") != null => ParseRss(root),
                _ => null
            };
        }
        catch { return null; }
    }

    private static Feed ParseRss(XElement root)
    {
        var channel = root.Element("channel") ?? root;
        var feed = new Feed
        {
            Title = channel.Element("title")?.Value.Trim() ?? "RSS Feed",
            Link = channel.Element("link")?.Value.Trim() ?? "",
            Description = channel.Element("description")?.Value.Trim() ?? "",
            FeedType = "RSS"
        };

        if (DateTime.TryParse(channel.Element("lastBuildDate")?.Value ?? channel.Element("pubDate")?.Value, out var d))
            feed.Updated = d;

        foreach (var item in channel.Elements("item"))
        {
            var fi = new FeedItem
            {
                Title = item.Element("title")?.Value.Trim() ?? "Untitled",
                Link = item.Element("link")?.Value.Trim() ?? "",
                Description = StripHtml(item.Element("description")?.Value ?? ""),
                Author = item.Element("author")?.Value.Trim() ?? item.Element("{http://purl.org/dc/elements/1.1/}creator")?.Value.Trim() ?? "",
                Category = item.Element("category")?.Value.Trim() ?? ""
            };
            if (DateTime.TryParse(item.Element("pubDate")?.Value, out var pd)) fi.Published = pd;
            feed.Items.Add(fi);
        }

        return feed;
    }

    private static Feed ParseAtom(XElement root)
    {
        XNamespace ns = "http://www.w3.org/2005/Atom";
        var feed = new Feed
        {
            Title = root.Element(ns + "title")?.Value.Trim() ?? "Atom Feed",
            Link = root.Elements(ns + "link").FirstOrDefault(l => l.Attribute("rel")?.Value != "self")?.Attribute("href")?.Value ?? "",
            Description = root.Element(ns + "subtitle")?.Value.Trim() ?? "",
            FeedType = "Atom"
        };

        if (DateTime.TryParse(root.Element(ns + "updated")?.Value, out var d))
            feed.Updated = d;

        foreach (var entry in root.Elements(ns + "entry"))
        {
            var fi = new FeedItem
            {
                Title = entry.Element(ns + "title")?.Value.Trim() ?? "Untitled",
                Link = entry.Elements(ns + "link").FirstOrDefault(l => l.Attribute("rel")?.Value != "enclosure")?.Attribute("href")?.Value ?? "",
                Description = StripHtml(entry.Element(ns + "summary")?.Value ?? entry.Element(ns + "content")?.Value ?? ""),
                Author = entry.Element(ns + "author")?.Element(ns + "name")?.Value.Trim() ?? ""
            };
            if (DateTime.TryParse(entry.Element(ns + "published")?.Value ?? entry.Element(ns + "updated")?.Value, out var pd))
                fi.Published = pd;
            feed.Items.Add(fi);
        }

        return feed;
    }

    public static string RenderFeedToHtml(Feed feed)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html><head><title>" + HtmlEncode(feed.Title) + "</title></head><body>");
        sb.AppendLine($"<h1>📡 {HtmlEncode(feed.Title)}</h1>");
        if (!string.IsNullOrEmpty(feed.Description))
            sb.AppendLine($"<p class=\"feed-desc\">{HtmlEncode(feed.Description)}</p>");
        sb.AppendLine($"<p><em>{feed.FeedType} Feed · {feed.Items.Count} items" +
                      (feed.Updated.HasValue ? $" · Updated {feed.Updated:MMM d, yyyy}" : "") + "</em></p>");
        sb.AppendLine("<hr/>");

        foreach (var item in feed.Items)
        {
            sb.AppendLine("<article>");
            sb.AppendLine($"<h2><a href=\"{HtmlEncode(item.Link)}\">{HtmlEncode(item.Title)}</a></h2>");
            var meta = new List<string>();
            if (!string.IsNullOrEmpty(item.Author)) meta.Add($"By {HtmlEncode(item.Author)}");
            if (item.Published.HasValue) meta.Add(item.Published.Value.ToString("MMMM d, yyyy"));
            if (!string.IsNullOrEmpty(item.Category)) meta.Add(HtmlEncode(item.Category));
            if (meta.Count > 0) sb.AppendLine($"<p><small>{string.Join(" · ", meta)}</small></p>");
            if (!string.IsNullOrEmpty(item.Description))
                sb.AppendLine($"<p>{HtmlEncode(item.Description.Length > 300 ? item.Description[..300] + "…" : item.Description)}</p>");
            if (!string.IsNullOrEmpty(item.Link))
                sb.AppendLine($"<p><a href=\"{HtmlEncode(item.Link)}\">Read more →</a></p>");
            sb.AppendLine("</article><hr/>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static string StripHtml(string html)
    {
        if (string.IsNullOrEmpty(html)) return html;
        return System.Text.RegularExpressions.Regex.Replace(html, "<[^>]+>", "").Trim();
    }

    private static string HtmlEncode(string text) =>
        System.Net.WebUtility.HtmlEncode(text ?? "");
}
