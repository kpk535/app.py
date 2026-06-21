using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using WebBrowser.Engine;

namespace WebBrowser;

public partial class MainWindow : Window
{
    private readonly HttpEngine _httpEngine;
    private readonly ProtocolHandler _protocolHandler;
    private readonly Stack<WebPage> _history = new();
    private readonly Stack<WebPage> _forwardHistory = new();
    private WebPage? _currentPage;

    public MainWindow()
    {
        InitializeComponent();
        _httpEngine = new HttpEngine();
        _protocolHandler = new ProtocolHandler(_httpEngine);
        LoadHomePage();
    }

    private async void LoadHomePage()
    {
        await NavigateToUrl("about:home");
    }

    private async void GoBtn_Click(object sender, RoutedEventArgs e)
    {
        var url = AddressBar.Text.Trim();
        if (string.IsNullOrEmpty(url)) return;

        await NavigateToUrl(url);
    }

    private async void AddressBar_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Return)
        {
            e.Handled = true;
            await NavigateToUrl(AddressBar.Text.Trim());
        }
    }

    private async Task NavigateToUrl(string url)
    {
        if (string.IsNullOrEmpty(url)) return;

        StatusText.Text = "Loading...";
        GoBtn.IsEnabled = false;

        try
        {
            var page = await _protocolHandler.FetchAsync(url);
            _history.Push(page);
            _forwardHistory.Clear();
            _currentPage = page;

            RenderPage(page);
            AddressBar.Text = page.Url;
            UpdateStatusBar();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
        }
        finally
        {
            GoBtn.IsEnabled = true;
        }
    }

    private void RenderPage(WebPage page)
    {
        ContentPanel.Children.Clear();

        if (string.IsNullOrEmpty(page.Html))
        {
            ContentPanel.Children.Add(new TextBlock
            {
                Text = page.PlainText,
                TextWrapping = TextWrapping.Wrap,
                Foreground = System.Windows.Media.Brushes.Red,
                Padding = new Thickness(10)
            });
            return;
        }

        try
        {
            var element = HtmlRenderer.RenderHtml(page.Html, page.Url);
            ContentPanel.Children.Add(element);
        }
        catch (Exception ex)
        {
            ContentPanel.Children.Add(new TextBlock
            {
                Text = $"Rendering error: {ex.Message}",
                TextWrapping = TextWrapping.Wrap,
                Foreground = System.Windows.Media.Brushes.Red,
                Padding = new Thickness(10)
            });
        }

        RenderLinks(page);
    }

    private void RenderLinks(WebPage page)
    {
        LinksListBox.ItemsSource = page.Links.Take(50).ToList();
    }

    private void LinksListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LinksListBox.SelectedItem is not WebLink link) return;

        var href = link.Href;
        if (href.StartsWith("#")) return;

        var baseUri = _currentPage?.Url ?? "http://localhost";
        var absoluteUrl = ResolveUrl(baseUri, href);

        AddressBar.Text = absoluteUrl;
        _ = NavigateToUrl(absoluteUrl);
    }

    private string ResolveUrl(string baseUrl, string relativeUrl)
    {
        if (relativeUrl.StartsWith("http://") || relativeUrl.StartsWith("https://"))
            return relativeUrl;

        try
        {
            var baseUri = new Uri(baseUrl);
            var resolved = new Uri(baseUri, relativeUrl);
            return resolved.ToString();
        }
        catch
        {
            return relativeUrl;
        }
    }

    private void BackBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_history.Count <= 1) return;

        _forwardHistory.Push(_history.Pop());
        if (_history.TryPeek(out var page))
        {
            _currentPage = page;
            RenderPage(page);
            AddressBar.Text = page.Url;
            UpdateStatusBar();
        }
    }

    private void ForwardBtn_Click(object sender, RoutedEventArgs e)
    {
        if (!_forwardHistory.TryPop(out var page)) return;

        _history.Push(page);
        _currentPage = page;
        RenderPage(page);
        AddressBar.Text = page.Url;
        UpdateStatusBar();
    }

    private void RefreshBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_currentPage == null) return;
        _ = NavigateToUrl(_currentPage.Url);
    }

    private void UpdateStatusBar()
    {
        if (_currentPage == null) return;

        StatusText.Text = $"Status: {_currentPage.StatusCode} | Title: {_currentPage.Title}";
        LoadTimeText.Text = $"Load time: {_currentPage.LoadTimeMs:F0}ms";
        BackBtn.IsEnabled = _history.Count > 1;
        ForwardBtn.IsEnabled = _forwardHistory.Count > 0;
    }
}
