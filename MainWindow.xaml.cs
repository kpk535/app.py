using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using WebBrowser.Engine;

namespace WebBrowser;

public class BrowserTab
{
    public string Id { get; } = Guid.NewGuid().ToString("N")[..8];
    public string Title { get; set; } = "New Tab";
    public string Url { get; set; } = "about:home";
    public bool IsLoading { get; set; }
    public WebPage? CurrentPage { get; set; }
    public FlowDocument? Document { get; set; }
    public Stack<string> BackStack { get; } = new();
    public Stack<string> ForwardStack { get; } = new();
    public bool IsReaderMode { get; set; }
    public bool IsBookmarked { get; set; }

    // UI references (not serialized)
    public object? Tag { get; set; }
    public System.Windows.Controls.TextBlock? TitleBlock { get; set; }
    public System.Windows.Controls.Border? TabBorder { get; set; }
}

public class HistoryEntry
{
    public string Title { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public DateTime VisitedAt { get; set; } = DateTime.Now;
}

public class BookmarkEntry
{
    public string Title { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public DateTime AddedAt { get; set; } = DateTime.Now;
}

public partial class MainWindow : Window
{
    // Engine
    private readonly HttpEngine _httpEngine = new();
    private readonly ProtocolHandler _protocolHandler;
    private readonly SearchEngine _searchEngine = new();
    private readonly HtmlRenderer _renderer = new();

    // State
    private readonly List<BrowserTab> _tabs = new();
    private BrowserTab? _activeTab;
    private readonly ObservableCollection<HistoryEntry> _history = new();
    private readonly ObservableCollection<BookmarkEntry> _bookmarks = new();
    private CancellationTokenSource? _loadCts;
    private bool _darkMode;
    private double _zoom = 1.0;
    private string _currentSidePanel = "links";

    // Find
    private TextPointer? _findStart;
    private readonly List<TextRange> _findMatches = new();
    private int _findIndex;

    // Commands
    public ICommand NewTabCommand { get; }
    public ICommand CloseTabCommand { get; }
    public ICommand FindCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand BookmarkCommand { get; }
    public ICommand ViewSourceCommand { get; }
    public ICommand BackCommand { get; }
    public ICommand ForwardCommand { get; }
    public ICommand ReaderModeCommand { get; }
    public ICommand DarkModeCommand { get; }

    public MainWindow()
    {
        InitializeComponent();

        _protocolHandler = new ProtocolHandler(_httpEngine);
        _protocolHandler.StatusChanged += (_, msg) => Dispatcher.InvokeAsync(() => StatusText.Text = msg);

        NewTabCommand = new RelayCommand(_ => CreateTab("about:home", activate: true));
        CloseTabCommand = new RelayCommand(_ => CloseActiveTab());
        FindCommand = new RelayCommand(_ => ToggleFindBar());
        RefreshCommand = new RelayCommand(_ => RefreshActive());
        BookmarkCommand = new RelayCommand(_ => ToggleBookmark());
        ViewSourceCommand = new RelayCommand(_ => ViewSource());
        BackCommand = new RelayCommand(_ => NavigateBack());
        ForwardCommand = new RelayCommand(_ => NavigateForward());
        ReaderModeCommand = new RelayCommand(_ => ToggleReaderMode());
        DarkModeCommand = new RelayCommand(_ => ToggleDarkMode());

        DataContext = this;

        LinksListBox.ItemsSource = null;
        HistoryListBox.ItemsSource = _history;
        BookmarksListBox.ItemsSource = _bookmarks;

        CreateTab("about:home", activate: true);
    }

    // ===================== TAB MANAGEMENT =====================

    private BrowserTab CreateTab(string url, bool activate = true)
    {
        var tab = new BrowserTab { Url = url, Title = "Loading…" };
        _tabs.Add(tab);
        BuildTabButton(tab);
        if (activate) ActivateTab(tab);
        _ = NavigateTab(tab, url);
        return tab;
    }

    private void BuildTabButton(BrowserTab tab)
    {
        var btn = new Button
        {
            Tag = tab,
            MinWidth = 120,
            MaxWidth = 200,
            Height = 36,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            Margin = new Thickness(1, 4, 1, 0)
        };

        var panel = new StackPanel { Orientation = Orientation.Horizontal };
        var title = new TextBlock
        {
            Tag = tab,
            Text = tab.Title,
            FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            MaxWidth = 130,
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(10, 0, 6, 0)
        };
        var close = new Button
        {
            Content = "✕",
            FontSize = 10,
            Width = 20, Height = 20,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            Foreground = Brushes.Gray,
            Margin = new Thickness(0, 0, 6, 0),
            Tag = tab,
            VerticalContentAlignment = VerticalAlignment.Center,
            HorizontalContentAlignment = HorizontalAlignment.Center
        };
        close.Click += CloseTabBtn_Click;
        panel.Children.Add(title);
        panel.Children.Add(close);
        btn.Content = panel;
        btn.Click += TabBtn_Click;

        tab.Tag = btn;
        tab.TitleBlock = title;

        var border = new Border
        {
            Tag = tab,
            Child = btn,
            CornerRadius = new CornerRadius(8, 8, 0, 0),
            Background = Brushes.Transparent
        };
        tab.TabBorder = border;
        TabBar.Children.Add(border);
    }

    private void ActivateTab(BrowserTab tab)
    {
        _activeTab = tab;

        foreach (BrowserTab t in _tabs)
        {
            if (t.TabBorder is Border b)
                b.Background = ReferenceEquals(t, tab)
                    ? Brushes.White
                    : Brushes.Transparent;
        }

        if (tab.Document != null)
            ContentViewer.Document = tab.Document;
        else
            ContentViewer.Document = null;

        AddressBar.Text = tab.Url;
        BackBtn.IsEnabled = tab.BackStack.Count > 0;
        ForwardBtn.IsEnabled = tab.ForwardStack.Count > 0;
        BookmarkIcon.Text = tab.IsBookmarked ? "★" : "☆";
        UpdateStatusFromTab(tab);
        RefreshLinksPanel(tab);
    }

    private void CloseActiveTab() => CloseTab(_activeTab);

    private void CloseTab(BrowserTab? tab)
    {
        if (tab == null || _tabs.Count <= 1) return;

        var idx = _tabs.IndexOf(tab);
        _tabs.Remove(tab);

        if (tab.TabBorder is Border b)
            TabBar.Children.Remove(b);

        if (ReferenceEquals(_activeTab, tab))
        {
            var next = idx < _tabs.Count ? _tabs[idx] : _tabs[^1];
            ActivateTab(next);
        }
    }

    // ===================== NAVIGATION =====================

    private async void GoBtn_Click(object s, RoutedEventArgs e) => await NavigateFromAddressBar();
    private async void AddressBar_KeyDown(object s, KeyEventArgs e)
    {
        if (e.Key == Key.Return) { e.Handled = true; await NavigateFromAddressBar(); }
    }

    private async Task NavigateFromAddressBar()
    {
        var input = AddressBar.Text.Trim();
        if (string.IsNullOrEmpty(input)) return;
        var url = _searchEngine.ProcessInput(input);
        if (_activeTab != null) await NavigateTab(_activeTab, url);
    }

    private async Task NavigateTab(BrowserTab tab, string url, bool addToHistory = true)
    {
        _loadCts?.Cancel();
        _loadCts = new CancellationTokenSource();
        var ct = _loadCts.Token;

        tab.IsLoading = true;
        tab.IsReaderMode = false;

        ShowLoading(true);
        StatusText.Text = $"Loading {url}…";

        try
        {
            var page = await _protocolHandler.FetchAsync(url, cancellationToken: ct);
            if (ct.IsCancellationRequested) return;

            if (addToHistory && tab.Url != url)
            {
                tab.BackStack.Push(tab.Url);
                tab.ForwardStack.Clear();
            }

            tab.Url = page.FinalUrl.Length > 0 ? page.FinalUrl : url;
            tab.CurrentPage = page;
            tab.Document = _renderer.Render(page.Html, tab.Url, Navigate, _darkMode);
            tab.Title = string.IsNullOrEmpty(page.Title) ? tab.Url : page.Title;
            tab.IsBookmarked = _bookmarks.Any(b => b.Url == tab.Url);

            AddressBar.Text = tab.Url;

            if (tab.TitleBlock is TextBlock tb)
                tb.Text = tab.Title.Length > 22 ? tab.Title[..22] + "…" : tab.Title;

            if (ReferenceEquals(tab, _activeTab))
            {
                ContentViewer.Document = tab.Document;
                RefreshLinksPanel(tab);
                BookmarkIcon.Text = tab.IsBookmarked ? "★" : "☆";
                BackBtn.IsEnabled = tab.BackStack.Count > 0;
                ForwardBtn.IsEnabled = tab.ForwardStack.Count > 0;
                SecureIcon.Visibility = page.IsSecure ? Visibility.Visible : Visibility.Collapsed;
                Title = $"{tab.Title} — Custom Browser";
            }

            UpdateStatusFromPage(page);

            if (addToHistory && !url.StartsWith("about:"))
                _history.Insert(0, new HistoryEntry { Title = page.Title, Url = tab.Url });
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            StatusText.Text = $"Error: {ex.Message}";
        }
        finally
        {
            tab.IsLoading = false;
            ShowLoading(false);
        }
    }

    private void Navigate(string url)
    {
        if (_activeTab != null)
            _ = NavigateTab(_activeTab, url);
    }

    private void NavigateBack()
    {
        if (_activeTab == null || _activeTab.BackStack.Count == 0) return;
        var prev = _activeTab.BackStack.Pop();
        _activeTab.ForwardStack.Push(_activeTab.Url);
        _ = NavigateTab(_activeTab, prev, addToHistory: false);
    }

    private void NavigateForward()
    {
        if (_activeTab == null || _activeTab.ForwardStack.Count == 0) return;
        var next = _activeTab.ForwardStack.Pop();
        _activeTab.BackStack.Push(_activeTab.Url);
        _ = NavigateTab(_activeTab, next, addToHistory: false);
    }

    private void RefreshActive()
    {
        if (_activeTab == null) return;
        _ = NavigateTab(_activeTab, _activeTab.Url, addToHistory: false);
    }

    // ===================== TOOLBAR EVENTS =====================

    private void BackBtn_Click(object s, RoutedEventArgs e) => NavigateBack();
    private void ForwardBtn_Click(object s, RoutedEventArgs e) => NavigateForward();
    private void RefreshBtn_Click(object s, RoutedEventArgs e) => RefreshActive();
    private void HomeBtn_Click(object s, RoutedEventArgs e) => Navigate("about:home");
    private void TabBtn_Click(object s, RoutedEventArgs e)
    {
        if (s is Button btn && btn.Tag is BrowserTab tab)
            ActivateTab(tab);
    }
    private void CloseTabBtn_Click(object s, RoutedEventArgs e)
    {
        if (s is Button btn && btn.Tag is BrowserTab tab)
            CloseTab(tab);
    }
    private void NewTabBtn_Click(object s, RoutedEventArgs e) => CreateTab("about:home", activate: true);

    // ===================== SIDEBAR =====================

    private void SideTab_Click(object s, RoutedEventArgs e)
    {
        if (s is not Button btn) return;
        var tag = btn.Tag?.ToString() ?? "links";
        SetSidePanel(tag);
    }

    private void SetSidePanel(string panel)
    {
        _currentSidePanel = panel;

        SideLinksPanel.Visibility = panel == "links" ? Visibility.Visible : Visibility.Collapsed;
        SideHistPanel.Visibility = panel == "history" ? Visibility.Visible : Visibility.Collapsed;
        SideBookPanel.Visibility = panel == "bookmarks" ? Visibility.Visible : Visibility.Collapsed;

        void Style(Button b, bool active)
        {
            b.Background = active ? (SolidColorBrush)Resources["PrimaryBrush"]! : Brushes.Transparent;
            b.Foreground = active ? Brushes.White : (SolidColorBrush)Resources["TextSecondaryBrush"]!;
            b.FontWeight = active ? FontWeights.SemiBold : FontWeights.Normal;
        }

        Style(SideLinksBtn, panel == "links");
        Style(SideHistBtn, panel == "history");
        Style(SideBookBtn, panel == "bookmarks");
    }

    private void RefreshLinksPanel(BrowserTab tab)
    {
        LinksListBox.ItemsSource = tab.CurrentPage?.Links.Take(100).ToList();
    }

    private void LinksListBox_SelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (LinksListBox.SelectedItem is not WebLink link) return;
        LinksListBox.SelectedItem = null;
        if (link.Href.StartsWith("#")) return;
        var resolved = _activeTab != null
            ? DomReader.ResolveUrl(_activeTab.Url, link.Href)
            : link.Href;
        Navigate(resolved);
    }

    private void HistoryListBox_SelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (HistoryListBox.SelectedItem is not HistoryEntry entry) return;
        HistoryListBox.SelectedItem = null;
        Navigate(entry.Url);
    }

    private void BookmarksListBox_SelectionChanged(object s, SelectionChangedEventArgs e)
    {
        if (BookmarksListBox.SelectedItem is not BookmarkEntry entry) return;
        BookmarksListBox.SelectedItem = null;
        Navigate(entry.Url);
    }

    private void SideSearch_TextChanged(object s, TextChangedEventArgs e)
    {
        var filter = SideSearch.Text.ToLower();

        if (_currentSidePanel == "links" && _activeTab?.CurrentPage != null)
        {
            var filtered = string.IsNullOrEmpty(filter)
                ? _activeTab.CurrentPage.Links.Take(100).ToList()
                : _activeTab.CurrentPage.Links.Where(l => l.Text.ToLower().Contains(filter) || l.Href.ToLower().Contains(filter)).Take(100).ToList();
            LinksListBox.ItemsSource = filtered;
        }
    }

    // ===================== FEATURES =====================

    private void ToggleBookmark()
    {
        if (_activeTab?.CurrentPage == null) return;
        var existing = _bookmarks.FirstOrDefault(b => b.Url == _activeTab.Url);
        if (existing != null)
        {
            _bookmarks.Remove(existing);
            _activeTab.IsBookmarked = false;
            BookmarkIcon.Text = "☆";
            StatusText.Text = "Bookmark removed.";
        }
        else
        {
            _bookmarks.Insert(0, new BookmarkEntry
            {
                Title = _activeTab.CurrentPage.Title,
                Url = _activeTab.Url
            });
            _activeTab.IsBookmarked = true;
            BookmarkIcon.Text = "★";
            StatusText.Text = "Page bookmarked!";
        }
    }

    private void BookmarkBtn_Click(object s, RoutedEventArgs e) => ToggleBookmark();

    private void ToggleReaderMode()
    {
        if (_activeTab?.CurrentPage == null) return;

        if (_activeTab.IsReaderMode)
        {
            _activeTab.Document = _renderer.Render(_activeTab.CurrentPage.Html, _activeTab.Url, Navigate, _darkMode);
            _activeTab.IsReaderMode = false;
            StatusText.Text = "Reader mode off.";
        }
        else
        {
            var clean = ReaderMode.ExtractArticle(_activeTab.CurrentPage.Html, _activeTab.CurrentPage.Title);
            _activeTab.Document = _renderer.Render(clean, _activeTab.Url, Navigate, _darkMode);
            _activeTab.IsReaderMode = true;
            StatusText.Text = "Reader mode — distraction-free view.";
        }

        if (ReferenceEquals(_activeTab, _activeTab))
            ContentViewer.Document = _activeTab.Document;
    }

    private void ReaderModeBtn_Click(object s, RoutedEventArgs e) => ToggleReaderMode();

    private void ToggleDarkMode()
    {
        _darkMode = !_darkMode;
        DarkIcon.Text = _darkMode ? "☀" : "🌙";
        Background = new SolidColorBrush(_darkMode ? Color.FromRgb(20, 20, 30) : Color.FromRgb(248, 249, 252));

        // Re-render current tab
        if (_activeTab?.CurrentPage != null)
        {
            _activeTab.Document = _renderer.Render(_activeTab.CurrentPage.Html, _activeTab.Url, Navigate, _darkMode);
            ContentViewer.Document = _activeTab.Document;
        }
        StatusText.Text = _darkMode ? "Dark mode on." : "Light mode on.";
    }

    private void DarkModeBtn_Click(object s, RoutedEventArgs e) => ToggleDarkMode();

    private void ViewSource()
    {
        if (_activeTab == null) return;
        CreateTab("view-source:" + _activeTab.Url, activate: true);
    }

    // ===================== FIND IN PAGE =====================

    private void ToggleFindBar()
    {
        if (FindBar.Visibility == Visibility.Visible)
        {
            FindBar.Visibility = Visibility.Collapsed;
            ClearFindHighlights();
        }
        else
        {
            FindBar.Visibility = Visibility.Visible;
            FindBox.Focus();
            FindBox.SelectAll();
        }
    }

    private void FindBtn_Click(object s, RoutedEventArgs e) => ToggleFindBar();
    private void FindClose_Click(object s, RoutedEventArgs e) => ToggleFindBar();
    private void FindBox_KeyDown(object s, KeyEventArgs e)
    {
        if (e.Key == Key.Return) FindNext();
        if (e.Key == Key.Escape) ToggleFindBar();
    }
    private void FindBox_TextChanged(object s, TextChangedEventArgs e) => FindAll();
    private void FindNext_Click(object s, RoutedEventArgs e) => FindNext();
    private void FindPrev_Click(object s, RoutedEventArgs e) => FindPrev();

    private void FindAll()
    {
        ClearFindHighlights();
        var term = FindBox.Text;
        if (string.IsNullOrEmpty(term) || ContentViewer.Document == null)
        {
            FindMatchCount.Text = "";
            return;
        }

        var doc = ContentViewer.Document;
        var pos = doc.ContentStart;
        _findMatches.Clear();

        while (pos != null && pos.CompareTo(doc.ContentEnd) < 0)
        {
            if (pos.GetPointerContext(LogicalDirection.Forward) == TextPointerContext.Text)
            {
                var text = pos.GetTextInRun(LogicalDirection.Forward);
                var idx = text.IndexOf(term, StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    var start = pos.GetPositionAtOffset(idx);
                    var end = pos.GetPositionAtOffset(idx + term.Length);
                    if (start != null && end != null)
                    {
                        var range = new TextRange(start, end);
                        range.ApplyPropertyValue(TextElement.BackgroundProperty,
                            new SolidColorBrush(Color.FromRgb(255, 220, 60)));
                        _findMatches.Add(range);
                    }
                }
            }
            pos = pos.GetNextContextPosition(LogicalDirection.Forward);
        }

        _findIndex = 0;
        FindMatchCount.Text = _findMatches.Count == 0 ? "No matches" : $"1 / {_findMatches.Count}";
        if (_findMatches.Count > 0) ScrollToMatch(0);
    }

    private void FindNext()
    {
        if (_findMatches.Count == 0) return;
        _findIndex = (_findIndex + 1) % _findMatches.Count;
        FindMatchCount.Text = $"{_findIndex + 1} / {_findMatches.Count}";
        ScrollToMatch(_findIndex);
    }

    private void FindPrev()
    {
        if (_findMatches.Count == 0) return;
        _findIndex = (_findIndex - 1 + _findMatches.Count) % _findMatches.Count;
        FindMatchCount.Text = $"{_findIndex + 1} / {_findMatches.Count}";
        ScrollToMatch(_findIndex);
    }

    private void ScrollToMatch(int index)
    {
        if (index >= _findMatches.Count) return;
        var match = _findMatches[index];
        match.Start.Paragraph?.BringIntoView();
    }

    private void ClearFindHighlights()
    {
        foreach (var r in _findMatches)
            r.ApplyPropertyValue(TextElement.BackgroundProperty, DependencyProperty.UnsetValue);
        _findMatches.Clear();
    }

    // ===================== ZOOM =====================

    private void MenuZoomIn_Click(object s, RoutedEventArgs e) => SetZoom(_zoom + 0.1);
    private void MenuZoomOut_Click(object s, RoutedEventArgs e) => SetZoom(_zoom - 0.1);
    private void MenuZoomReset_Click(object s, RoutedEventArgs e) => SetZoom(1.0);
    private void ZoomText_Click(object s, MouseButtonEventArgs e) => SetZoom(1.0);

    private void SetZoom(double z)
    {
        _zoom = Math.Clamp(z, 0.5, 3.0);
        if (ContentViewer.Document != null)
            ContentViewer.Document.FontSize = 14 * _zoom;
        ZoomText.Text = $"{_zoom * 100:F0}%";
    }

    // ===================== MENU EVENTS =====================

    private void MenuNewTab_Click(object s, RoutedEventArgs e) => CreateTab("about:home", activate: true);
    private void MenuCloseTab_Click(object s, RoutedEventArgs e) => CloseActiveTab();
    private void MenuViewSource_Click(object s, RoutedEventArgs e) => ViewSource();
    private void MenuExit_Click(object s, RoutedEventArgs e) => Application.Current.Shutdown();
    private void MenuReaderMode_Click(object s, RoutedEventArgs e) => ToggleReaderMode();
    private void MenuDarkMode_Click(object s, RoutedEventArgs e) => ToggleDarkMode();
    private void MenuBack_Click(object s, RoutedEventArgs e) => NavigateBack();
    private void MenuForward_Click(object s, RoutedEventArgs e) => NavigateForward();
    private void MenuShowHistory_Click(object s, RoutedEventArgs e) => SetSidePanel("history");
    private void MenuClearHistory_Click(object s, RoutedEventArgs e)
    {
        _history.Clear();
        StatusText.Text = "History cleared.";
    }
    private void MenuBookmark_Click(object s, RoutedEventArgs e) => ToggleBookmark();
    private void MenuFind_Click(object s, RoutedEventArgs e) => ToggleFindBar();
    private void MenuSettings_Click(object s, RoutedEventArgs e) => Navigate("about:settings");
    private void MenuAbout_Click(object s, RoutedEventArgs e) => Navigate("about:home");
    private void MenuPageInfo_Click(object s, RoutedEventArgs e) => ShowPageInfo();

    private void ShowPageInfo()
    {
        if (_activeTab?.CurrentPage == null) return;
        var p = _activeTab.CurrentPage;
        var info = $"URL: {p.FinalUrl}\n" +
                   $"Title: {p.Title}\n" +
                   $"Status: {p.StatusCode} {p.StatusMessage}\n" +
                   $"Load time: {p.LoadTimeMs:F0}ms\n" +
                   $"Content type: {p.ContentType}\n" +
                   $"Encoding: {p.Encoding}\n" +
                   $"Links: {p.Links.Count}\n" +
                   $"Images: {p.Images.Count}\n" +
                   $"Secure: {p.IsSecure}\n" +
                   $"From cache: {p.IsFromCache}\n" +
                   (string.IsNullOrEmpty(p.Meta.Description) ? "" : $"Description: {p.Meta.Description}");
        MessageBox.Show(info, "Page Info", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void AddressBar_GotFocus(object s, RoutedEventArgs e) => AddressBar.SelectAll();

    // ===================== UI HELPERS =====================

    private void ShowLoading(bool loading)
    {
        RefreshIcon.Text = loading ? "✕" : "↻";
        LoadProgress.Visibility = loading ? Visibility.Visible : Visibility.Collapsed;
        if (loading)
        {
            var anim = new DoubleAnimation(0, 85, TimeSpan.FromSeconds(8));
            LoadProgress.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, anim);
        }
        else
        {
            LoadProgress.BeginAnimation(System.Windows.Controls.Primitives.RangeBase.ValueProperty, null);
            LoadProgress.Value = 100;
        }
    }

    private void UpdateStatusFromPage(WebPage page)
    {
        var secure = page.IsSecure ? "🔒 " : "";
        var cached = page.IsFromCache ? " [cache]" : "";
        StatusText.Text = $"{secure}{page.StatusCode} {page.StatusMessage}{cached}";
        LoadTimeText.Text = $"{page.LoadTimeMs:F0}ms · {page.Links.Count} links · {page.Images.Count} images";
    }

    private void UpdateStatusFromTab(BrowserTab tab)
    {
        if (tab.CurrentPage != null) UpdateStatusFromPage(tab.CurrentPage);
        else StatusText.Text = tab.Url;
        Title = $"{tab.Title} — Custom Browser";
    }
}

// ===================== RELAY COMMAND =====================

public class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? p) => _canExecute?.Invoke(p) ?? true;
    public void Execute(object? p) => _execute(p);
}
