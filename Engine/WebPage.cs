namespace WebBrowser.Engine;

public class WebPage
{
    public string Url { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Html { get; set; } = string.Empty;
    public string PlainText { get; set; } = string.Empty;
    public List<WebLink> Links { get; set; } = new();
    public Dictionary<string, string> Headers { get; set; } = new();
    public int StatusCode { get; set; }
    public DateTime LoadedAt { get; set; } = DateTime.UtcNow;
    public double LoadTimeMs { get; set; }
}

public class WebLink
{
    public string Text { get; set; } = string.Empty;
    public string Href { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
}
