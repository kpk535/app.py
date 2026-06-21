using System.Net;
using System.Text;

namespace WebBrowser.Engine;

public class HttpEngine
{
    private readonly HttpClient _httpClient;
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 CustomBrowser/2.0";

    public event EventHandler<string>? StatusChanged;

    public HttpEngine()
    {
        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = cookies,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 10,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };

        _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        _httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", UserAgent);
        _httpClient.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
        _httpClient.DefaultRequestHeaders.Add("Accept-Language", "en-US,en;q=0.9");
        _httpClient.DefaultRequestHeaders.Add("DNT", "1");
        _httpClient.DefaultRequestHeaders.Add("Upgrade-Insecure-Requests", "1");
    }

    public async Task<WebPage> FetchPageAsync(string url, CancellationToken cancellationToken = default)
    {
        var page = new WebPage { Url = url };
        var sw = System.Diagnostics.Stopwatch.StartNew();

        if (!url.StartsWith("http://") && !url.StartsWith("https://"))
            url = "https://" + url;

        StatusChanged?.Invoke(this, $"Connecting to {new Uri(url).Host}…");

        try
        {
            var response = await SendWithRetryAsync(url, cancellationToken);
            sw.Stop();

            page.FinalUrl = response.RequestMessage?.RequestUri?.ToString() ?? url;
            page.StatusCode = (int)response.StatusCode;
            page.StatusMessage = response.ReasonPhrase ?? "";
            page.IsSecure = url.StartsWith("https://");

            foreach (var h in response.Headers)
                page.Headers[h.Key] = string.Join(", ", h.Value);
            foreach (var h in response.Content.Headers)
                page.Headers[h.Key] = string.Join(", ", h.Value);

            page.ContentLength = response.Content.Headers.ContentLength ?? 0;

            var mimeType = response.Content.Headers.ContentType?.MediaType ?? "";
            var charSet = response.Content.Headers.ContentType?.CharSet ?? "utf-8";

            StatusChanged?.Invoke(this, $"Downloading ({page.StatusCode})…");

            byte[] bytes;
            try { bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken); }
            catch (OperationCanceledException) { throw; }
            catch { bytes = []; }

            var encoding = TryGetEncoding(charSet) ?? Encoding.UTF8;
            page.RawContent = encoding.GetString(bytes);
            page.Encoding = encoding.WebName.ToUpper();

            page.ContentType = ContentTypeHandler.DetectContentType(mimeType, page.FinalUrl, page.RawContent);

            if (page.ContentType == ContentType.Html)
            {
                page.Html = page.RawContent;

                if (FeedReader.IsFeed(page.RawContent, mimeType))
                {
                    var feed = FeedReader.Parse(page.RawContent);
                    if (feed != null)
                    {
                        page.ContentType = ContentType.Feed;
                        page.Html = FeedReader.RenderFeedToHtml(feed);
                        page.Title = feed.Title;
                    }
                }
                else
                {
                    DomReader.EnrichPage(page);
                }
            }
            else if (page.ContentType == ContentType.Xml && FeedReader.IsFeed(page.RawContent, mimeType))
            {
                var feed = FeedReader.Parse(page.RawContent);
                if (feed != null)
                {
                    page.ContentType = ContentType.Feed;
                    page.Html = FeedReader.RenderFeedToHtml(feed);
                    page.Title = feed.Title;
                }
            }
            else
            {
                page.Html = ContentTypeHandler.ConvertToHtml(page.RawContent, page.ContentType, page.FinalUrl);
                page.Title = System.IO.Path.GetFileName(new Uri(page.FinalUrl).AbsolutePath);
                if (string.IsNullOrEmpty(page.Title)) page.Title = page.FinalUrl;
            }

            page.LoadTimeMs = sw.ElapsedMilliseconds;
            StatusChanged?.Invoke(this, $"Done ({page.LoadTimeMs:F0}ms)");
            return page;
        }
        catch (OperationCanceledException)
        {
            page.ErrorMessage = "Request cancelled.";
            page.StatusCode = 0;
            return page;
        }
        catch (HttpRequestException ex)
        {
            sw.Stop();
            page.ErrorMessage = $"Network error: {ex.Message}";
            page.StatusCode = (int)(ex.StatusCode ?? 0);
            page.LoadTimeMs = sw.ElapsedMilliseconds;
            page.Html = BuildErrorPage(url, page.ErrorMessage, page.StatusCode);
            StatusChanged?.Invoke(this, $"Error: {ex.Message}");
            return page;
        }
        catch (Exception ex)
        {
            sw.Stop();
            page.ErrorMessage = ex.Message;
            page.StatusCode = 0;
            page.LoadTimeMs = sw.ElapsedMilliseconds;
            page.Html = BuildErrorPage(url, ex.Message, 0);
            StatusChanged?.Invoke(this, $"Error: {ex.Message}");
            return page;
        }
    }

    private async Task<HttpResponseMessage> SendWithRetryAsync(string url, CancellationToken ct)
    {
        Exception? last = null;
        int[] delays = [0, 1000, 2000, 4000];

        for (int i = 0; i < delays.Length; i++)
        {
            if (delays[i] > 0)
            {
                StatusChanged?.Invoke(this, $"Retrying… (attempt {i + 1})");
                await Task.Delay(delays[i], ct);
            }

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, url);
                var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseContentRead, ct);
                if ((int)response.StatusCode < 500) return response;
                last = new HttpRequestException($"Server returned {(int)response.StatusCode} {response.ReasonPhrase}", null, response.StatusCode);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { last = ex; }
        }

        throw last!;
    }

    public async Task<WebPage> FetchSourceAsync(string url, CancellationToken cancellationToken = default)
    {
        var page = await FetchPageAsync(url, cancellationToken);
        var sourceHtml = ContentTypeHandler.ConvertToHtml(page.RawContent, ContentType.PlainText, url);
        page.Html = $@"<!DOCTYPE html>
<html><head><title>Source: {System.Net.WebUtility.HtmlEncode(url)}</title></head>
<body>{sourceHtml}</body></html>";
        return page;
    }

    private static Encoding? TryGetEncoding(string charset)
    {
        if (string.IsNullOrEmpty(charset)) return null;
        try { return Encoding.GetEncoding(charset); } catch { return null; }
    }

    private static string BuildErrorPage(string url, string message, int code)
    {
        var codeLabel = code > 0 ? $"{code} Error" : "Connection Error";
        var advice = code switch
        {
            404 => "The page was not found. Check the URL and try again.",
            403 => "Access is forbidden to this page.",
            500 => "The server encountered an internal error.",
            503 => "The server is temporarily unavailable.",
            0 => "Could not connect to the server. Check your internet connection.",
            _ => "An unexpected error occurred."
        };

        return $@"<!DOCTYPE html>
<html>
<head><title>Error: {codeLabel}</title></head>
<body>
  <h1>⚠ {codeLabel}</h1>
  <p><strong>URL:</strong> {System.Net.WebUtility.HtmlEncode(url)}</p>
  <p><strong>Reason:</strong> {System.Net.WebUtility.HtmlEncode(message)}</p>
  <p>{advice}</p>
  <p><a href=""{System.Net.WebUtility.HtmlEncode(url)}"">Try Again</a></p>
</body>
</html>";
    }
}
