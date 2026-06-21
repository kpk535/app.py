using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using HtmlAgilityPack;

namespace WebBrowser.Engine;

public static class ReaderMode
{
    private static readonly string[] ContentTags = { "article", "main", "[role=main]", ".article", ".post", ".content" };

    public static string ExtractArticle(string html, string title = "")
    {
        var doc = new HtmlDocument();
        doc.LoadHtml(html);

        RemoveNoise(doc);

        var articleNode = FindArticleNode(doc);
        var content = articleNode != null
            ? CleanNode(articleNode)
            : ExtractByHeuristic(doc);

        return BuildReaderHtml(title, content);
    }

    private static void RemoveNoise(HtmlDocument doc)
    {
        var noiseSelectors = new[] {
            "//script", "//style", "//noscript", "//iframe",
            "//nav", "//header", "//footer", "//aside",
            "//form", "//button", "//select",
            "//*[contains(@class,'ad')]", "//*[contains(@class,'sidebar')]",
            "//*[contains(@class,'menu')]", "//*[contains(@class,'nav')]",
            "//*[contains(@class,'comment')]", "//*[contains(@class,'share')]",
            "//*[contains(@class,'social')]", "//*[contains(@class,'widget')]",
            "//*[contains(@id,'ad')]", "//*[contains(@id,'sidebar')]"
        };

        foreach (var selector in noiseSelectors)
        {
            var nodes = doc.DocumentNode.SelectNodes(selector);
            if (nodes != null)
                foreach (var node in nodes.ToList())
                    node.Remove();
        }
    }

    private static HtmlNode? FindArticleNode(HtmlDocument doc)
    {
        var candidates = new[] {
            "//article", "//main", "//*[@role='main']",
            "//*[contains(@class,'article')]", "//*[contains(@class,'post-content')]",
            "//*[contains(@class,'entry-content')]", "//*[contains(@class,'page-content')]",
            "//*[contains(@id,'article')]", "//*[contains(@id,'content')]"
        };

        foreach (var xpath in candidates)
        {
            var node = doc.DocumentNode.SelectSingleNode(xpath);
            if (node != null && GetTextLength(node) > 200)
                return node;
        }

        return null;
    }

    private static HtmlNode ExtractByHeuristic(HtmlDocument doc)
    {
        var body = doc.DocumentNode.SelectSingleNode("//body") ?? doc.DocumentNode;
        var candidates = body.SelectNodes("//div|//section|//p") ?? Enumerable.Empty<HtmlNode>().ToHtmlNodeCollection();

        HtmlNode? best = null;
        int bestScore = 0;

        foreach (var node in candidates)
        {
            var score = ScoreNode(node);
            if (score > bestScore)
            {
                bestScore = score;
                best = node;
            }
        }

        return best ?? body;
    }

    private static int ScoreNode(HtmlNode node)
    {
        var text = node.InnerText.Trim();
        var textLen = text.Length;
        if (textLen < 100) return 0;

        var score = textLen / 10;
        score += node.SelectNodes(".//p")?.Count * 20 ?? 0;
        score += node.SelectNodes(".//h1|.//h2|.//h3")?.Count * 10 ?? 0;
        score -= node.SelectNodes(".//a")?.Count * 3 ?? 0;

        var className = (node.GetAttributeValue("class", "") + " " + node.GetAttributeValue("id", "")).ToLower();
        if (className.Contains("article") || className.Contains("content") || className.Contains("post")) score += 50;
        if (className.Contains("comment") || className.Contains("sidebar") || className.Contains("ad")) score -= 100;

        return Math.Max(0, score);
    }

    private static string CleanNode(HtmlNode node)
    {
        var sb = new System.Text.StringBuilder();
        BuildCleanHtml(node, sb);
        return sb.ToString();
    }

    private static void BuildCleanHtml(HtmlNode node, System.Text.StringBuilder sb)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            var text = HtmlEntity.DeEntitize(node.InnerText);
            if (!string.IsNullOrWhiteSpace(text))
                sb.Append(System.Net.WebUtility.HtmlEncode(text));
            return;
        }

        var allowed = new HashSet<string> {
            "p", "h1", "h2", "h3", "h4", "h5", "h6",
            "ul", "ol", "li", "blockquote", "pre", "code",
            "strong", "b", "em", "i", "u", "br", "hr",
            "a", "table", "tr", "td", "th", "thead", "tbody"
        };

        var tag = node.Name.ToLower();

        if (tag == "#document" || tag == "html" || tag == "body" || tag == "div" ||
            tag == "article" || tag == "main" || tag == "section")
        {
            foreach (var child in node.ChildNodes)
                BuildCleanHtml(child, sb);
            return;
        }

        if (!allowed.Contains(tag))
        {
            foreach (var child in node.ChildNodes)
                BuildCleanHtml(child, sb);
            return;
        }

        sb.Append($"<{tag}");
        if (tag == "a")
        {
            var href = node.GetAttributeValue("href", "");
            if (!string.IsNullOrEmpty(href)) sb.Append($" href=\"{System.Net.WebUtility.HtmlEncode(href)}\"");
        }
        sb.Append('>');
        foreach (var child in node.ChildNodes)
            BuildCleanHtml(child, sb);
        sb.Append($"</{tag}>");
    }

    private static string BuildReaderHtml(string title, string content)
    {
        return $@"<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"">
    <title>{System.Net.WebUtility.HtmlEncode(title)}</title>
    <style>
        body {{
            font-family: 'Georgia', 'Times New Roman', serif;
            font-size: 18px;
            line-height: 1.8;
            color: #2d2d2d;
            background: #fefefe;
            max-width: 680px;
            margin: 60px auto;
            padding: 0 20px 80px;
        }}
        h1, h2, h3, h4 {{
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.3;
            margin-top: 1.8em;
            margin-bottom: 0.4em;
            color: #111;
        }}
        h1 {{ font-size: 2em; }}
        h2 {{ font-size: 1.5em; border-bottom: 2px solid #f0f0f0; padding-bottom: 0.3em; }}
        p {{ margin: 1em 0; }}
        a {{ color: #667eea; text-decoration: underline; }}
        blockquote {{
            border-left: 4px solid #667eea;
            margin: 1.5em 0;
            padding: 0.5em 1.5em;
            color: #555;
            background: #f9f9ff;
            border-radius: 0 4px 4px 0;
        }}
        pre, code {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85em;
            background: #f5f5f5;
            border-radius: 4px;
        }}
        pre {{ padding: 1em; overflow-x: auto; }}
        code {{ padding: 0.15em 0.4em; }}
        img {{ max-width: 100%; height: auto; border-radius: 4px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        td, th {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
        th {{ background: #f5f5f5; font-weight: bold; }}
        hr {{ border: none; border-top: 2px solid #f0f0f0; margin: 2em 0; }}
    </style>
</head>
<body>
    {(string.IsNullOrEmpty(title) ? "" : $"<h1>{System.Net.WebUtility.HtmlEncode(title)}</h1>")}
    {content}
</body>
</html>";
    }

    private static int GetTextLength(HtmlNode node) => node.InnerText.Trim().Length;
}

internal static class HtmlNodeExtensions
{
    internal static HtmlAgilityPack.HtmlNodeCollection ToHtmlNodeCollection(this IEnumerable<HtmlNode> nodes)
    {
        var col = new HtmlAgilityPack.HtmlNodeCollection(null);
        foreach (var n in nodes) col.Add(n);
        return col;
    }
}
