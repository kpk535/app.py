using HtmlAgilityPack;

namespace WebBrowser.Engine;

public static class DomReader
{
    public static void EnrichPage(WebPage page)
    {
        if (string.IsNullOrEmpty(page.Html)) return;

        var doc = new HtmlDocument();
        doc.LoadHtml(page.Html);

        ExtractTitle(page, doc);
        ExtractMeta(page, doc);
        ExtractLinks(page, doc);
        ExtractImages(page, doc);
        ExtractHeadings(page, doc);
        ExtractPlainText(page, doc);
    }

    private static void ExtractTitle(WebPage page, HtmlDocument doc)
    {
        var titleNode = doc.DocumentNode.SelectSingleNode("//title");
        if (titleNode != null)
            page.Title = HtmlEntity.DeEntitize(titleNode.InnerText.Trim());
    }

    private static void ExtractMeta(WebPage page, HtmlDocument doc)
    {
        var metas = doc.DocumentNode.SelectNodes("//meta") ?? Enumerable.Empty<HtmlNode>();
        foreach (var meta in metas)
        {
            var name = meta.GetAttributeValue("name", "").ToLower();
            var prop = meta.GetAttributeValue("property", "").ToLower();
            var content = meta.GetAttributeValue("content", "");
            var charset = meta.GetAttributeValue("charset", "");
            var httpEquiv = meta.GetAttributeValue("http-equiv", "").ToLower();

            if (!string.IsNullOrEmpty(charset)) page.Meta.Charset = charset;

            switch (name)
            {
                case "description": page.Meta.Description = content; break;
                case "keywords": page.Meta.Keywords = content; break;
                case "author": page.Meta.Author = content; break;
                case "robots": page.Meta.Robots = content; break;
                case "theme-color": page.Meta.ThemeColor = content; break;
                case "viewport": page.Meta.Viewport = content; break;
            }

            switch (prop)
            {
                case "og:title": page.Meta.OgTitle = content; break;
                case "og:description": page.Meta.OgDescription = content; break;
                case "og:image": page.Meta.OgImage = content; break;
                case "og:type": page.Meta.OgType = content; break;
                case "og:site_name": page.Meta.OgSiteName = content; break;
            }

            if (httpEquiv == "content-type" && content.Contains("charset="))
                page.Meta.Charset = content.Split("charset=")[1].Trim();
        }

        var links = doc.DocumentNode.SelectNodes("//link") ?? Enumerable.Empty<HtmlNode>();
        foreach (var link in links)
        {
            var rel = link.GetAttributeValue("rel", "").ToLower();
            var href = link.GetAttributeValue("href", "");
            var type = link.GetAttributeValue("type", "").ToLower();

            if (rel == "canonical") page.Meta.Canonical = href;

            if ((rel == "alternate" || rel == "feed") &&
                (type.Contains("rss") || type.Contains("atom") || href.Contains("feed") || href.Contains("rss")))
            {
                page.Meta.FeedUrl = href;
                page.Meta.FeedType = type.Contains("atom") ? "Atom" : "RSS";
            }
        }
    }

    private static void ExtractLinks(WebPage page, HtmlDocument doc)
    {
        var baseUrl = page.FinalUrl.Length > 0 ? page.FinalUrl : page.Url;
        var baseHost = TryGetHost(baseUrl);

        var nodes = doc.DocumentNode.SelectNodes("//a[@href]") ?? Enumerable.Empty<HtmlNode>();
        foreach (var node in nodes)
        {
            var href = node.GetAttributeValue("href", "").Trim();
            if (string.IsNullOrEmpty(href) || href.StartsWith("javascript:") || href.StartsWith("mailto:"))
                continue;

            var text = HtmlEntity.DeEntitize(node.InnerText).Trim();
            if (string.IsNullOrEmpty(text))
                text = node.GetAttributeValue("title", href);

            var resolved = ResolveUrl(baseUrl, href);
            var isExternal = baseHost != null && TryGetHost(resolved) is { } h && h != baseHost;

            page.Links.Add(new WebLink
            {
                Href = href,
                Text = text.Length > 100 ? text[..100] + "…" : text,
                Title = node.GetAttributeValue("title", ""),
                Rel = node.GetAttributeValue("rel", ""),
                IsExternal = isExternal
            });
        }
    }

    private static void ExtractImages(WebPage page, HtmlDocument doc)
    {
        var nodes = doc.DocumentNode.SelectNodes("//img[@src]") ?? Enumerable.Empty<HtmlNode>();
        foreach (var node in nodes)
        {
            var src = node.GetAttributeValue("src", "").Trim();
            if (string.IsNullOrEmpty(src)) continue;

            page.Images.Add(new WebImage
            {
                Src = src,
                Alt = node.GetAttributeValue("alt", ""),
                Width = int.TryParse(node.GetAttributeValue("width", ""), out var w) ? w : 0,
                Height = int.TryParse(node.GetAttributeValue("height", ""), out var h) ? h : 0
            });
        }
    }

    private static void ExtractHeadings(WebPage page, HtmlDocument doc)
    {
        for (int level = 1; level <= 6; level++)
        {
            var nodes = doc.DocumentNode.SelectNodes($"//h{level}") ?? Enumerable.Empty<HtmlNode>();
            foreach (var node in nodes)
            {
                page.Headings.Add(new WebHeading
                {
                    Level = level,
                    Text = HtmlEntity.DeEntitize(node.InnerText).Trim(),
                    Id = node.GetAttributeValue("id", "")
                });
            }
        }

        page.Headings.Sort((a, b) =>
        {
            var aPos = GetNodePosition(a, doc);
            var bPos = GetNodePosition(b, doc);
            return aPos.CompareTo(bPos);
        });
    }

    private static int GetNodePosition(WebHeading heading, HtmlDocument doc)
    {
        var node = doc.DocumentNode.SelectSingleNode($"//h{heading.Level}[normalize-space(.)='{heading.Text.Replace("'", "\\'")}']");
        return node?.StreamPosition ?? 0;
    }

    private static void ExtractPlainText(WebPage page, HtmlDocument doc)
    {
        var body = doc.DocumentNode.SelectSingleNode("//body") ?? doc.DocumentNode;
        var scripts = body.SelectNodes("//script|//style|//noscript");
        if (scripts != null)
            foreach (var s in scripts) s.Remove();

        var sb = new System.Text.StringBuilder();
        ExtractTextRecursive(body, sb);
        page.PlainText = System.Text.RegularExpressions.Regex.Replace(sb.ToString(), @"\s{3,}", "\n\n").Trim();
    }

    private static void ExtractTextRecursive(HtmlNode node, System.Text.StringBuilder sb)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            var text = HtmlEntity.DeEntitize(node.InnerText);
            if (!string.IsNullOrWhiteSpace(text))
                sb.Append(text);
            return;
        }

        var blockTags = new HashSet<string> { "p", "div", "h1", "h2", "h3", "h4", "h5", "h6",
            "li", "br", "tr", "blockquote", "pre", "article", "section", "header", "footer" };
        var tag = node.Name.ToLower();

        if (blockTags.Contains(tag)) sb.AppendLine();

        foreach (var child in node.ChildNodes)
            ExtractTextRecursive(child, sb);

        if (blockTags.Contains(tag)) sb.AppendLine();
    }

    public static string ResolveUrl(string baseUrl, string relativeUrl)
    {
        if (string.IsNullOrEmpty(relativeUrl)) return baseUrl;
        if (relativeUrl.StartsWith("http://") || relativeUrl.StartsWith("https://") ||
            relativeUrl.StartsWith("game://") || relativeUrl.StartsWith("about:") ||
            relativeUrl.StartsWith("file://") || relativeUrl.StartsWith("data:"))
            return relativeUrl;
        if (relativeUrl.StartsWith("//"))
        {
            var scheme = baseUrl.StartsWith("https") ? "https" : "http";
            return scheme + ":" + relativeUrl;
        }
        try
        {
            return new Uri(new Uri(baseUrl), relativeUrl).ToString();
        }
        catch
        {
            return relativeUrl;
        }
    }

    private static string? TryGetHost(string url)
    {
        try { return new Uri(url).Host; } catch { return null; }
    }
}
