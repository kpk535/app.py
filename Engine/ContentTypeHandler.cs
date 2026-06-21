using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace WebBrowser.Engine;

public static class ContentTypeHandler
{
    public static ContentType DetectContentType(string mimeType, string url, string content)
    {
        var mime = mimeType.ToLower().Split(';')[0].Trim();

        if (mime.Contains("html") || mime.Contains("xhtml")) return ContentType.Html;
        if (mime.Contains("json")) return ContentType.Json;
        if (mime.Contains("xml") || mime.Contains("rss") || mime.Contains("atom")) return ContentType.Xml;
        if (mime.Contains("text/plain")) return ContentType.PlainText;
        if (mime.StartsWith("image/")) return ContentType.Image;

        // Sniff by URL extension
        var lower = url.ToLower().Split('?')[0];
        if (lower.EndsWith(".json")) return ContentType.Json;
        if (lower.EndsWith(".xml") || lower.EndsWith(".rss") || lower.EndsWith(".atom")) return ContentType.Xml;
        if (lower.EndsWith(".txt") || lower.EndsWith(".md") || lower.EndsWith(".csv")) return ContentType.PlainText;
        if (lower.EndsWith(".png") || lower.EndsWith(".jpg") || lower.EndsWith(".gif") ||
            lower.EndsWith(".svg") || lower.EndsWith(".webp") || lower.EndsWith(".ico")) return ContentType.Image;

        // Sniff by content
        var trimmed = content.TrimStart();
        if (trimmed.StartsWith("<") && (trimmed.Contains("<html") || trimmed.Contains("<!DOCTYPE")))
            return ContentType.Html;
        if (trimmed.StartsWith("{") || trimmed.StartsWith("[")) return ContentType.Json;
        if (trimmed.StartsWith("<?xml") || trimmed.StartsWith("<rss") || trimmed.StartsWith("<feed"))
            return ContentType.Xml;

        return ContentType.Unknown;
    }

    public static string ConvertToHtml(string content, ContentType type, string url = "")
    {
        return type switch
        {
            ContentType.Json => RenderJson(content),
            ContentType.Xml => RenderXml(content),
            ContentType.PlainText => RenderPlainText(content),
            ContentType.Image => RenderImage(url),
            ContentType.Feed => content,
            _ => content
        };
    }

    private static string RenderJson(string json)
    {
        string pretty;
        try
        {
            using var doc = JsonDocument.Parse(json);
            pretty = JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch { pretty = json; }

        var highlighted = SyntaxHighlightJson(pretty);
        return $@"<!DOCTYPE html>
<html>
<head><title>JSON Viewer</title>
<style>
  body {{ font-family: 'Consolas', monospace; font-size: 13px; background: #1e1e2e; color: #cdd6f4;
          margin: 0; padding: 20px; line-height: 1.6; }}
  .json-string {{ color: #a6e3a1; }}
  .json-number {{ color: #fab387; }}
  .json-bool {{ color: #89b4fa; }}
  .json-null {{ color: #6c7086; }}
  .json-key {{ color: #89dceb; }}
  pre {{ margin: 0; white-space: pre-wrap; word-break: break-all; }}
  h3 {{ color: #cba6f7; font-size: 11px; margin: 0 0 12px; letter-spacing: 1px; text-transform: uppercase; }}
</style></head>
<body>
<h3>📄 JSON Viewer</h3>
<pre>{highlighted}</pre>
</body></html>";
    }

    private static string SyntaxHighlightJson(string json)
    {
        var result = new System.Text.StringBuilder();
        int i = 0;
        while (i < json.Length)
        {
            char c = json[i];
            if (c == '"')
            {
                int start = i++;
                while (i < json.Length && (json[i] != '"' || json[i - 1] == '\\')) i++;
                i++;
                var str = json[start..i];
                var isKey = i < json.Length && json[i..].TrimStart().StartsWith(":");
                result.Append(isKey
                    ? $"<span class=\"json-key\">{System.Net.WebUtility.HtmlEncode(str)}</span>"
                    : $"<span class=\"json-string\">{System.Net.WebUtility.HtmlEncode(str)}</span>");
            }
            else if (char.IsDigit(c) || (c == '-' && i + 1 < json.Length && char.IsDigit(json[i + 1])))
            {
                int start = i++;
                while (i < json.Length && (char.IsDigit(json[i]) || json[i] == '.' || json[i] == 'e' || json[i] == 'E' || json[i] == '-' || json[i] == '+')) i++;
                result.Append($"<span class=\"json-number\">{json[start..i]}</span>");
            }
            else if (json[i..].StartsWith("true") || json[i..].StartsWith("false"))
            {
                var word = json[i..].StartsWith("true") ? "true" : "false";
                result.Append($"<span class=\"json-bool\">{word}</span>");
                i += word.Length;
            }
            else if (json[i..].StartsWith("null"))
            {
                result.Append("<span class=\"json-null\">null</span>");
                i += 4;
            }
            else
            {
                result.Append(System.Net.WebUtility.HtmlEncode(c.ToString()));
                i++;
            }
        }
        return result.ToString();
    }

    private static string RenderXml(string xml)
    {
        string pretty;
        try
        {
            var doc = XDocument.Parse(xml);
            pretty = doc.ToString();
        }
        catch { pretty = xml; }

        return $@"<!DOCTYPE html>
<html>
<head><title>XML Viewer</title>
<style>
  body {{ font-family: 'Consolas', monospace; font-size: 13px; background: #fafafa; color: #333;
          margin: 0; padding: 20px; line-height: 1.6; }}
  .xml-tag {{ color: #0070c1; }}
  .xml-attr {{ color: #e07400; }}
  .xml-value {{ color: #008000; }}
  pre {{ margin: 0; white-space: pre-wrap; }}
  h3 {{ color: #555; font-size: 11px; margin: 0 0 12px; text-transform: uppercase; letter-spacing: 1px; }}
</style></head>
<body>
<h3>📄 XML Viewer</h3>
<pre>{SyntaxHighlightXml(pretty)}</pre>
</body></html>";
    }

    private static string SyntaxHighlightXml(string xml)
    {
        var result = System.Net.WebUtility.HtmlEncode(xml);
        result = System.Text.RegularExpressions.Regex.Replace(result,
            @"(&lt;[/?!]?)(\w[\w:-]*)([^&]*?&gt;)",
            m => $"<span class=\"xml-tag\">{m.Groups[1].Value}</span>" +
                 $"<span class=\"xml-tag\">{m.Groups[2].Value}</span>" +
                 $"{m.Groups[3].Value}");
        return result;
    }

    private static string RenderPlainText(string text)
    {
        var lines = text.Split('\n');
        var numbered = string.Join("\n", lines.Select((l, i) =>
            $"<tr><td class=\"ln\">{i + 1}</td><td class=\"lt\">{System.Net.WebUtility.HtmlEncode(l)}</td></tr>"));

        return $@"<!DOCTYPE html>
<html>
<head><title>Plain Text</title>
<style>
  body {{ font-family: 'Consolas', monospace; font-size: 13px; background: #fff; margin: 0; padding: 0; }}
  table {{ border-collapse: collapse; width: 100%; }}
  .ln {{ color: #999; background: #f5f5f5; padding: 0 12px; text-align: right; user-select: none;
         border-right: 1px solid #e0e0e0; white-space: nowrap; width: 1%; font-size: 11px; }}
  .lt {{ padding: 0 16px; white-space: pre; color: #333; }}
  tr:hover {{ background: #f9f9f9; }}
</style></head>
<body><table><tbody>{numbered}</tbody></table></body></html>";
    }

    private static string RenderImage(string url)
    {
        return $@"<!DOCTYPE html>
<html>
<head><title>Image</title>
<style>
  body {{ display:flex; justify-content:center; align-items:center; min-height:100vh;
          margin:0; background: #1a1a2e; }}
  img {{ max-width:90vw; max-height:90vh; object-fit:contain;
         box-shadow: 0 20px 60px rgba(0,0,0,0.5); border-radius: 4px; }}
</style></head>
<body><img src=""{System.Net.WebUtility.HtmlEncode(url)}"" alt=""Image""/></body></html>";
    }
}
