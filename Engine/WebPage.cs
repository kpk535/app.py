namespace WebBrowser.Engine;

public enum ContentType { Html, Json, Xml, PlainText, Feed, Image, Binary, Unknown }

public class WebPage
{
    public string Url { get; set; } = string.Empty;
    public string FinalUrl { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Html { get; set; } = string.Empty;
    public string RawContent { get; set; } = string.Empty;
    public string PlainText { get; set; } = string.Empty;
    public string Encoding { get; set; } = "UTF-8";
    public ContentType ContentType { get; set; } = ContentType.Html;
    public PageMeta Meta { get; set; } = new();
    public List<WebLink> Links { get; set; } = new();
    public List<WebImage> Images { get; set; } = new();
    public List<WebHeading> Headings { get; set; } = new();
    public Dictionary<string, string> Headers { get; set; } = new();
    public int StatusCode { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public long ContentLength { get; set; }
    public DateTime LoadedAt { get; set; } = DateTime.UtcNow;
    public double LoadTimeMs { get; set; }
    public bool IsSecure { get; set; }
    public bool IsFromCache { get; set; }
    public string? ErrorMessage { get; set; }
    public bool HasError => ErrorMessage != null;
}

public class PageMeta
{
    public string Description { get; set; } = string.Empty;
    public string Keywords { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public string Canonical { get; set; } = string.Empty;
    public string Charset { get; set; } = string.Empty;
    public string Robots { get; set; } = string.Empty;
    public string OgTitle { get; set; } = string.Empty;
    public string OgDescription { get; set; } = string.Empty;
    public string OgImage { get; set; } = string.Empty;
    public string OgType { get; set; } = string.Empty;
    public string OgSiteName { get; set; } = string.Empty;
    public string FeedUrl { get; set; } = string.Empty;
    public string FeedType { get; set; } = string.Empty;
    public string ThemeColor { get; set; } = string.Empty;
    public string Viewport { get; set; } = string.Empty;
}

public class WebLink
{
    public string Text { get; set; } = string.Empty;
    public string Href { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Rel { get; set; } = string.Empty;
    public bool IsExternal { get; set; }
}

public class WebImage
{
    public string Src { get; set; } = string.Empty;
    public string Alt { get; set; } = string.Empty;
    public int Width { get; set; }
    public int Height { get; set; }
}

public class WebHeading
{
    public int Level { get; set; }
    public string Text { get; set; } = string.Empty;
    public string Id { get; set; } = string.Empty;
}
