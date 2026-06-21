using System;
using System.Collections.Generic;

namespace WebBrowser.Engine;

public class SearchEngine
{
    private readonly Dictionary<string, string> _engines = new(StringComparer.OrdinalIgnoreCase)
    {
        ["google"] = "https://www.google.com/search?q={0}",
        ["bing"] = "https://www.bing.com/search?q={0}",
        ["ddg"] = "https://duckduckgo.com/?q={0}",
        ["duck"] = "https://duckduckgo.com/?q={0}",
        ["wiki"] = "https://en.wikipedia.org/w/index.php?search={0}",
        ["gh"] = "https://github.com/search?q={0}",
        ["yt"] = "https://www.youtube.com/results?search_query={0}",
    };

    public string DefaultEngine { get; set; } = "https://duckduckgo.com/?q={0}";

    public string ProcessInput(string input)
    {
        input = input.Trim();
        if (string.IsNullOrEmpty(input)) return "about:home";

        // Already a URL
        if (IsUrl(input)) return NormalizeUrl(input);

        // Bang command: !g search term, !yt video
        if (input.StartsWith('!'))
        {
            var space = input.IndexOf(' ');
            if (space > 0)
            {
                var bang = input[1..space].ToLower();
                var query = input[(space + 1)..].Trim();
                if (_engines.TryGetValue(bang, out var eng))
                    return string.Format(eng, Uri.EscapeDataString(query));
            }
        }

        // Keyword shortcut: "google something"
        foreach (var (keyword, template) in _engines)
        {
            if (input.StartsWith(keyword + " ", StringComparison.OrdinalIgnoreCase))
            {
                var query = input[(keyword.Length + 1)..].Trim();
                return string.Format(template, Uri.EscapeDataString(query));
            }
        }

        // Looks like a domain (has dot, no spaces)
        if (!input.Contains(' ') && input.Contains('.') && !input.Contains(' '))
            return NormalizeUrl(input);

        // Default: search
        return string.Format(DefaultEngine, Uri.EscapeDataString(input));
    }

    private static bool IsUrl(string input)
    {
        return input.StartsWith("http://") || input.StartsWith("https://") ||
               input.StartsWith("game://") || input.StartsWith("about:") ||
               input.StartsWith("file://") || input.StartsWith("data:") ||
               input.StartsWith("view-source:");
    }

    private static string NormalizeUrl(string input)
    {
        if (input.StartsWith("http://") || input.StartsWith("https://") ||
            input.StartsWith("game://") || input.StartsWith("about:") ||
            input.StartsWith("file://"))
            return input;
        return "https://" + input;
    }
}
