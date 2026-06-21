using System.Text.RegularExpressions;
using System.Windows.Media;

namespace WebBrowser.Engine;

public class CssProperties
{
    public Color? Color { get; set; }
    public Color? BackgroundColor { get; set; }
    public double? FontSize { get; set; }
    public bool? Bold { get; set; }
    public bool? Italic { get; set; }
    public bool? Underline { get; set; }
    public bool? Strikethrough { get; set; }
    public string? FontFamily { get; set; }
    public string? TextAlign { get; set; }
    public double? MarginTop { get; set; }
    public double? MarginBottom { get; set; }
    public double? PaddingLeft { get; set; }
    public double? Opacity { get; set; }
}

public static class CssEngine
{
    private static readonly Dictionary<string, Color> _namedColors = new(StringComparer.OrdinalIgnoreCase)
    {
        ["black"] = Colors.Black, ["white"] = Colors.White, ["red"] = Colors.Red,
        ["green"] = Colors.Green, ["blue"] = Colors.Blue, ["yellow"] = Colors.Yellow,
        ["orange"] = Colors.Orange, ["purple"] = Colors.Purple, ["pink"] = Colors.Pink,
        ["gray"] = Colors.Gray, ["grey"] = Colors.Gray, ["navy"] = Colors.Navy,
        ["teal"] = Colors.Teal, ["maroon"] = Color.FromRgb(128, 0, 0),
        ["silver"] = Colors.Silver, ["gold"] = Colors.Gold, ["cyan"] = Colors.Cyan,
        ["magenta"] = Colors.Magenta, ["lime"] = Colors.Lime, ["brown"] = Colors.Brown,
        ["crimson"] = Colors.Crimson, ["coral"] = Colors.Coral, ["indigo"] = Colors.Indigo,
        ["violet"] = Colors.Violet, ["aqua"] = Colors.Aqua, ["fuchsia"] = Colors.Fuchsia,
        ["transparent"] = Colors.Transparent,
    };

    public static CssProperties ParseInlineStyle(string style)
    {
        var props = new CssProperties();
        if (string.IsNullOrWhiteSpace(style)) return props;

        foreach (var declaration in style.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var idx = declaration.IndexOf(':');
            if (idx < 0) continue;

            var property = declaration[..idx].Trim().ToLower();
            var value = declaration[(idx + 1)..].Trim();

            ApplyProperty(props, property, value);
        }

        return props;
    }

    public static Dictionary<string, CssProperties> ParseStylesheet(string css)
    {
        var rules = new Dictionary<string, CssProperties>(StringComparer.OrdinalIgnoreCase);
        var rulePattern = new Regex(@"([^{]+)\{([^}]*)\}", RegexOptions.Singleline);

        foreach (Match match in rulePattern.Matches(css))
        {
            var selectors = match.Groups[1].Value.Trim();
            var declarations = match.Groups[2].Value.Trim();
            var props = ParseInlineStyle(declarations);

            foreach (var selector in selectors.Split(','))
            {
                var sel = selector.Trim();
                if (!string.IsNullOrEmpty(sel))
                    rules[sel] = props;
            }
        }

        return rules;
    }

    private static void ApplyProperty(CssProperties props, string property, string value)
    {
        switch (property)
        {
            case "color":
                props.Color = ParseColor(value);
                break;
            case "background-color" or "background":
                props.BackgroundColor = ParseColor(value);
                break;
            case "font-size":
                props.FontSize = ParseFontSize(value);
                break;
            case "font-weight":
                props.Bold = value is "bold" or "bolder" || (int.TryParse(value, out var w) && w >= 600);
                break;
            case "font-style":
                props.Italic = value == "italic" || value == "oblique";
                break;
            case "text-decoration":
                props.Underline = value.Contains("underline");
                props.Strikethrough = value.Contains("line-through");
                break;
            case "font-family":
                props.FontFamily = ParseFontFamily(value);
                break;
            case "text-align":
                props.TextAlign = value;
                break;
            case "margin-top":
                props.MarginTop = ParsePixelValue(value);
                break;
            case "margin-bottom":
                props.MarginBottom = ParsePixelValue(value);
                break;
            case "padding-left":
                props.PaddingLeft = ParsePixelValue(value);
                break;
            case "opacity":
                if (double.TryParse(value, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var op))
                    props.Opacity = op;
                break;
        }
    }

    public static Color? ParseColor(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "inherit" || value == "currentColor")
            return null;

        value = value.Trim();

        if (_namedColors.TryGetValue(value, out var named))
            return named;

        if (value.StartsWith('#'))
        {
            var hex = value[1..];
            if (hex.Length == 3)
                hex = $"{hex[0]}{hex[0]}{hex[1]}{hex[1]}{hex[2]}{hex[2]}";
            if (hex.Length == 6 && uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var rgb))
                return Color.FromRgb((byte)(rgb >> 16), (byte)(rgb >> 8 & 0xFF), (byte)(rgb & 0xFF));
            if (hex.Length == 8 && uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var argb))
                return Color.FromArgb((byte)(argb >> 24), (byte)(argb >> 16 & 0xFF), (byte)(argb >> 8 & 0xFF), (byte)(argb & 0xFF));
        }

        var rgbMatch = Regex.Match(value, @"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\s*\)");
        if (rgbMatch.Success)
        {
            byte r = byte.Parse(rgbMatch.Groups[1].Value);
            byte g = byte.Parse(rgbMatch.Groups[2].Value);
            byte b = byte.Parse(rgbMatch.Groups[3].Value);
            byte a = 255;
            if (rgbMatch.Groups[4].Success && double.TryParse(rgbMatch.Groups[4].Value,
                System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var alpha))
                a = (byte)(alpha * 255);
            return Color.FromArgb(a, r, g, b);
        }

        return null;
    }

    private static double? ParseFontSize(string value)
    {
        var map = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase)
        {
            ["xx-small"] = 9, ["x-small"] = 10, ["small"] = 12, ["medium"] = 14,
            ["large"] = 16, ["x-large"] = 20, ["xx-large"] = 26, ["xxx-large"] = 32
        };
        if (map.TryGetValue(value, out var mapped)) return mapped;

        if (value.EndsWith("px") && double.TryParse(value[..^2],
            System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var px))
            return px * 0.75;
        if (value.EndsWith("pt") && double.TryParse(value[..^2],
            System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var pt))
            return pt;
        if (value.EndsWith("em") && double.TryParse(value[..^2],
            System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var em))
            return em * 14;

        return null;
    }

    private static double? ParsePixelValue(string value)
    {
        if (value.EndsWith("px") && double.TryParse(value[..^2],
            System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var v))
            return v;
        return null;
    }

    private static string? ParseFontFamily(string value)
    {
        var family = value.Split(',')[0].Trim().Trim('"', '\'');
        return string.IsNullOrEmpty(family) ? null : family;
    }
}
