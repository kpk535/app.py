# Custom Web Browser in C#

A modern web browser built entirely in C# with a rich WPF GUI and a custom HTML engine.

## Architecture

### Core Components

1. **Engine**
   - `HttpEngine.cs` - Custom HTTP client with cookie management and redirect handling
   - `HtmlRenderer.cs` - WPF-based HTML to visual element converter
   - `WebPage.cs` - Page model with links, headers, and metadata
   - `ProtocolHandler.cs` - Multi-protocol support (http, https, game://, about:)

2. **UI**
   - `MainWindow.xaml` - Beautiful browser interface with address bar, navigation, status bar
   - `MainWindow.xaml.cs` - Event handlers and page navigation logic

3. **Game**
   - `GameEngine.cs` - Security challenge engine with 20 levels
   - `LocalGameServer.cs` - Request handler for game:// protocol

### Key Features

- ✨ **Custom HTTP Engine**: Handles HTTP/HTTPS requests with proper header management
- 🎨 **WPF Rendering**: Converts HTML to beautiful WPF elements
- 🔗 **Link Extraction**: Automatically extracts and displays all links
- 📜 **Browser History**: Full back/forward navigation
- 🎮 **Hacking Game**: 20 levels of security challenges
- 🚀 **Protocol Support**: http, https, game://, about:

## Building

### Prerequisites
- .NET 8.0 SDK
- Visual Studio 2022 or higher (optional)

### Build
```bash
dotnet build
```

### Run
```bash
dotnet run
```

## Usage

### Navigation
1. Type a URL in the address bar
2. Press Enter or click "Go"
3. Click links in the sidebar or in the rendered page content
4. Use Back/Forward buttons for history navigation
5. Use Refresh to reload current page

### Supported URLs
- **http://** / **https://** - Standard web URLs
- **game://localhost/game/login** - Hacking game
- **about:home** - Home page
- **about:blank** - Blank page

### Playing the Hacking Game

1. Navigate to `game://localhost/game/login`
2. Default admin credentials: `admin` / `adminpass`
3. Or login with generated user accounts
4. Complete security challenges across 20 levels
5. Each level teaches different vulnerability types

## Vulnerability Levels

### SQL Injection (Levels 1, 2, 5, 6, 11, 12)
- Basic: `' OR '1'='1`
- Time-based: `SLEEP(5)`
- Union-based injection
- Blind SQL injection

### Cross-Site Scripting (Levels 3, 4, 7, 8, 13)
- Reflected XSS: `<script>alert('XSS')</script>`
- Stored XSS attacks
- DOM-based XSS
- Filter bypassing

### Authentication Bypass (Levels 9, 17, 18)
- Username/password bypass
- MFA circumvention
- Session manipulation

### File Inclusion (Levels 10, 15, 16)
- Local File Inclusion (LFI): `../../../etc/passwd`
- Remote File Inclusion (RFI)
- Path traversal

### Code Execution (Levels 14, 19, 20)
- CSRF attacks
- Remote Code Execution
- Zero-day vulnerabilities

## Code Structure

```
WebBrowser/
├── Engine/
│   ├── HttpEngine.cs         # HTTP client
│   ├── HtmlRenderer.cs       # HTML to WPF converter
│   ├── WebPage.cs            # Page model
│   └── ProtocolHandler.cs    # Protocol router
├── Game/
│   ├── GameEngine.cs         # Game logic
│   └── LocalGameServer.cs    # Game request handler
├── App.xaml(.cs)             # Application entry point
├── MainWindow.xaml(.cs)      # Main UI
└── WebBrowser.csproj         # Project file
```

## Design Highlights

### Custom HTTP Engine
- Uses `System.Net.Http.HttpClient` for requests
- Maintains `CookieContainer` for session management
- Automatic gzip decompression
- Configurable timeouts and redirects
- Custom User-Agent header

### HTML Rendering Strategy
- Parses HTML with HtmlAgilityPack
- Converts to WPF `RichTextBox` content
- Supports semantic elements (h1-h3, p, div, ul, ol, etc.)
- Preserves formatting (bold, italic, links)
- Graceful fallback on rendering errors

### Protocol Handler
- Routes requests to appropriate handlers
- Supports multiple custom protocols
- Seamless integration with HTTP engine
- Extensible for new protocols

### Game Integration
- In-process game server (no external dependencies)
- Session management with unique IDs
- State persistence across requests
- Difficulty progression system

## Performance Considerations

1. **Page Loading**: Async/await for non-blocking network I/O
2. **Rendering**: Efficient WPF element creation
3. **Memory**: Stack-based history management
4. **Caching**: HTTP caching via HttpClient

## Security Notes

⚠️ **For Educational Purposes Only**

This browser is designed for learning about web vulnerabilities in a controlled environment. The included game is intentionally vulnerable for educational demonstration.

### Browser Security
- No JavaScript execution (intentional limitation)
- No plugin support
- No cached credentials storage
- Safe HTML rendering without script execution

## Future Enhancements

- [ ] JavaScript engine integration (with limitations)
- [ ] CSS styling improvements
- [ ] Image loading and display
- [ ] Form submission handling
- [ ] Download manager
- [ ] Bookmarks and favorites
- [ ] Search engine integration
- [ ] Proxy support
- [ ] Certificate validation UI
- [ ] Developer tools

## License

Educational use only. Built as a learning project.

---

**Built with ❤️ using C# and WPF**
