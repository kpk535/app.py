using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using HtmlAgilityPack;

namespace WebBrowser.Engine;

public class HtmlRenderer
{
    private string _baseUrl = "";
    private Action<string>? _navigate;
    private Dictionary<string, CssProperties> _stylesheet = new();
    private bool _darkMode;

    private static readonly HashSet<string> BlockTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "div", "p", "h1", "h2", "h3", "h4", "h5", "h6",
        "ul", "ol", "li", "table", "thead", "tbody", "tfoot",
        "tr", "th", "td", "blockquote", "pre", "hr", "br",
        "article", "section", "main", "header", "footer", "nav",
        "aside", "figure", "figcaption", "address", "details", "summary",
        "dl", "dt", "dd"
    };

    public FlowDocument Render(string html, string baseUrl, Action<string> navigateCallback, bool darkMode = false)
    {
        _baseUrl = baseUrl;
        _navigate = navigateCallback;
        _darkMode = darkMode;

        var doc = new FlowDocument
        {
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 14,
            PagePadding = new Thickness(36, 24, 36, 36),
            LineHeight = 22,
            Foreground = new SolidColorBrush(darkMode ? Color.FromRgb(220, 220, 220) : Color.FromRgb(30, 30, 30)),
            Background = new SolidColorBrush(darkMode ? Color.FromRgb(28, 28, 35) : Colors.White)
        };

        try
        {
            var htmlDoc = new HtmlDocument();
            htmlDoc.LoadHtml(html);

            ExtractStylesheet(htmlDoc);

            var body = htmlDoc.DocumentNode.SelectSingleNode("//body") ?? htmlDoc.DocumentNode;
            RenderBlockChildren(body, doc.Blocks);

            if (doc.Blocks.Count == 0)
                doc.Blocks.Add(new Paragraph(new Run("(empty page)")));
        }
        catch (Exception ex)
        {
            doc.Blocks.Clear();
            doc.Blocks.Add(new Paragraph(new Run($"Rendering error: {ex.Message}"))
            {
                Foreground = Brushes.Red
            });
        }

        return doc;
    }

    private void ExtractStylesheet(HtmlDocument doc)
    {
        _stylesheet.Clear();
        var styleNodes = doc.DocumentNode.SelectNodes("//style");
        if (styleNodes == null) return;

        var combined = string.Join("\n", styleNodes.Select(n => n.InnerText));
        _stylesheet = CssEngine.ParseStylesheet(combined);
    }

    private void RenderBlockChildren(HtmlNode container, BlockCollection blocks)
    {
        var pendingInlines = new List<Inline>();

        void FlushInlines()
        {
            if (pendingInlines.Count == 0) return;
            var hasContent = pendingInlines.Any(i => i is not LineBreak);
            if (!hasContent) { pendingInlines.Clear(); return; }
            var para = new Paragraph();
            para.Margin = new Thickness(0, 4, 0, 4);
            foreach (var i in pendingInlines) para.Inlines.Add(i);
            blocks.Add(para);
            pendingInlines.Clear();
        }

        foreach (var child in container.ChildNodes)
        {
            if (IsBlockElement(child))
            {
                FlushInlines();
                var rendered = RenderBlock(child);
                if (rendered != null) blocks.Add(rendered);
            }
            else
            {
                var inlines = RenderInlines(child).ToList();
                pendingInlines.AddRange(inlines);
            }
        }

        FlushInlines();
    }

    private bool IsBlockElement(HtmlNode node)
    {
        if (node.NodeType == HtmlNodeType.Text) return false;
        return BlockTags.Contains(node.Name);
    }

    private Block? RenderBlock(HtmlNode node)
    {
        var tag = node.Name.ToLower();
        var style = GetNodeStyle(node);

        return tag switch
        {
            "h1" or "h2" or "h3" or "h4" or "h5" or "h6" => RenderHeading(node, tag, style),
            "p" or "address" => RenderParagraph(node, style),
            "ul" or "ol" => RenderList(node, tag == "ol"),
            "table" => RenderTable(node),
            "pre" => RenderPreformatted(node),
            "blockquote" => RenderBlockquote(node),
            "hr" => RenderHorizontalRule(),
            "dl" => RenderDefinitionList(node),
            "details" => RenderDetails(node),
            "figure" => RenderFigure(node),
            "div" or "section" or "article" or "main" or "header"
                or "footer" or "nav" or "aside" or "form" => RenderContainer(node, style),
            "br" => null,
            _ => RenderContainer(node, style)
        };
    }

    private Paragraph RenderHeading(HtmlNode node, string tag, CssProperties style)
    {
        var level = int.Parse(tag[1].ToString());
        var sizes = new[] { 0.0, 28, 22, 18, 16, 14, 13 };
        var colors = new[] {
            null,
            _darkMode ? Color.FromRgb(180, 160, 255) : Color.FromRgb(80, 60, 200),
            _darkMode ? Color.FromRgb(140, 200, 255) : Color.FromRgb(30, 90, 180),
            _darkMode ? Color.FromRgb(120, 220, 160) : Color.FromRgb(20, 120, 60),
            _darkMode ? Color.FromRgb(255, 200, 120) : Color.FromRgb(140, 80, 0),
            (Color?)null, (Color?)null
        };

        var para = new Paragraph
        {
            FontSize = style.FontSize ?? sizes[level],
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, level <= 2 ? 18 : 12, 0, 6),
            Foreground = colors[level].HasValue
                ? new SolidColorBrush(colors[level]!.Value)
                : (style.Color.HasValue ? new SolidColorBrush(style.Color.Value) : null)
        };

        if (level <= 2)
        {
            para.BorderBrush = new SolidColorBrush(_darkMode ? Color.FromRgb(60, 60, 80) : Color.FromRgb(220, 220, 230));
            para.BorderThickness = new Thickness(0, 0, 0, 1);
            para.Padding = new Thickness(0, 0, 0, 6);
        }

        foreach (var inline in RenderInlineChildren(node))
            para.Inlines.Add(inline);

        return para;
    }

    private Paragraph RenderParagraph(HtmlNode node, CssProperties style)
    {
        var para = new Paragraph
        {
            Margin = new Thickness(0, 2, 0, 10),
            LineHeight = 22
        };

        ApplyStyleToParagraph(para, style);

        foreach (var inline in RenderInlineChildren(node))
            para.Inlines.Add(inline);

        return para;
    }

    private List RenderList(HtmlNode node, bool ordered)
    {
        var list = new List
        {
            MarkerStyle = ordered ? TextMarkerStyle.Decimal : TextMarkerStyle.Disc,
            Margin = new Thickness(0, 4, 0, 10),
            Padding = new Thickness(24, 0, 0, 0)
        };

        foreach (var child in node.ChildNodes)
        {
            var tag = child.Name.ToLower();
            if (tag != "li") continue;

            var item = new ListItem { Margin = new Thickness(0, 2, 0, 2) };
            var hasSub = child.ChildNodes.Any(c => c.Name is "ul" or "ol");

            if (hasSub)
            {
                RenderBlockChildren(child, item.Blocks);
            }
            else
            {
                var para = new Paragraph { Margin = new Thickness(0) };
                foreach (var inline in RenderInlineChildren(child))
                    para.Inlines.Add(inline);
                item.Blocks.Add(para);
            }

            list.ListItems.Add(item);
        }

        return list;
    }

    private Table RenderTable(HtmlNode node)
    {
        var table = new Table
        {
            Margin = new Thickness(0, 8, 0, 16),
            CellSpacing = 0,
            BorderBrush = new SolidColorBrush(_darkMode ? Color.FromRgb(60, 65, 80) : Color.FromRgb(200, 200, 210)),
            BorderThickness = new Thickness(1)
        };

        // Gather all rows
        var rows = new List<HtmlNode>();
        CollectRows(node, rows);

        if (rows.Count == 0) return table;

        // Determine max columns
        var maxCols = rows.Max(r => r.ChildNodes.Count(c => c.Name is "td" or "th"));
        for (int i = 0; i < maxCols; i++)
            table.Columns.Add(new TableColumn());

        var rg = new TableRowGroup();
        table.RowGroups.Add(rg);

        bool firstRow = true;
        foreach (var row in rows)
        {
            var tr = new TableRow();
            bool isHeader = row.ParentNode?.Name.ToLower() == "thead" || firstRow && row.ChildNodes.Any(c => c.Name == "th");

            foreach (var cell in row.ChildNodes.Where(c => c.Name is "td" or "th"))
            {
                var tc = new TableCell
                {
                    Padding = new Thickness(8, 6, 8, 6),
                    BorderBrush = new SolidColorBrush(_darkMode ? Color.FromRgb(60, 65, 80) : Color.FromRgb(210, 210, 215)),
                    BorderThickness = new Thickness(0, 0, 1, 1)
                };

                if (isHeader || cell.Name == "th")
                {
                    tc.Background = new SolidColorBrush(_darkMode ? Color.FromRgb(45, 45, 60) : Color.FromRgb(245, 245, 250));
                    var p = new Paragraph { FontWeight = FontWeights.SemiBold, Margin = new Thickness(0) };
                    foreach (var inline in RenderInlineChildren(cell)) p.Inlines.Add(inline);
                    tc.Blocks.Add(p);
                }
                else
                {
                    var p = new Paragraph { Margin = new Thickness(0) };
                    foreach (var inline in RenderInlineChildren(cell)) p.Inlines.Add(inline);
                    tc.Blocks.Add(p);
                }

                tr.Cells.Add(tc);
            }

            rg.Rows.Add(tr);
            firstRow = false;
        }

        return table;
    }

    private void CollectRows(HtmlNode node, List<HtmlNode> rows)
    {
        foreach (var child in node.ChildNodes)
        {
            var tag = child.Name.ToLower();
            if (tag == "tr") rows.Add(child);
            else if (tag is "thead" or "tbody" or "tfoot") CollectRows(child, rows);
        }
    }

    private Section RenderPreformatted(HtmlNode node)
    {
        var section = new Section { Margin = new Thickness(0, 8, 0, 16) };
        var bg = _darkMode ? Color.FromRgb(30, 30, 42) : Color.FromRgb(248, 248, 252);
        var border = _darkMode ? Color.FromRgb(55, 55, 75) : Color.FromRgb(220, 220, 230);

        var para = new Paragraph
        {
            FontFamily = new FontFamily("Consolas, Cascadia Code, Courier New"),
            FontSize = 12,
            LineHeight = 18,
            Background = new SolidColorBrush(bg),
            Foreground = new SolidColorBrush(_darkMode ? Color.FromRgb(200, 210, 240) : Color.FromRgb(40, 40, 60)),
            BorderBrush = new SolidColorBrush(border),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(16, 12, 16, 12),
            Margin = new Thickness(0)
        };

        var text = HtmlEntity.DeEntitize(node.InnerText);
        para.Inlines.Add(new Run(text));
        section.Blocks.Add(para);
        return section;
    }

    private Section RenderBlockquote(HtmlNode node)
    {
        var section = new Section
        {
            Margin = new Thickness(0, 8, 0, 12),
            Padding = new Thickness(16, 8, 16, 8),
            BorderBrush = new SolidColorBrush(_darkMode ? Color.FromRgb(120, 100, 200) : Color.FromRgb(100, 120, 234)),
            BorderThickness = new Thickness(4, 0, 0, 0),
            Background = new SolidColorBrush(_darkMode ? Color.FromRgb(35, 32, 55) : Color.FromRgb(248, 248, 255))
        };

        RenderBlockChildren(node, section.Blocks);
        return section;
    }

    private BlockUIContainer RenderHorizontalRule()
    {
        var sep = new Separator
        {
            Background = new SolidColorBrush(_darkMode ? Color.FromRgb(60, 60, 80) : Color.FromRgb(210, 210, 220)),
            Height = 1,
            Margin = new Thickness(0, 12, 0, 12)
        };
        return new BlockUIContainer(sep) { Margin = new Thickness(0, 8, 0, 8) };
    }

    private Section RenderDefinitionList(HtmlNode node)
    {
        var section = new Section { Margin = new Thickness(0, 4, 0, 12) };
        foreach (var child in node.ChildNodes)
        {
            var tag = child.Name.ToLower();
            if (tag == "dt")
            {
                var dt = new Paragraph
                {
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 6, 0, 2),
                    Foreground = new SolidColorBrush(_darkMode ? Color.FromRgb(170, 160, 255) : Color.FromRgb(60, 60, 180))
                };
                foreach (var inline in RenderInlineChildren(child)) dt.Inlines.Add(inline);
                section.Blocks.Add(dt);
            }
            else if (tag == "dd")
            {
                var dd = new Paragraph { Margin = new Thickness(24, 0, 0, 4) };
                foreach (var inline in RenderInlineChildren(child)) dd.Inlines.Add(inline);
                section.Blocks.Add(dd);
            }
        }
        return section;
    }

    private Section RenderDetails(HtmlNode node)
    {
        var section = new Section
        {
            BorderBrush = new SolidColorBrush(_darkMode ? Color.FromRgb(60, 60, 80) : Color.FromRgb(200, 200, 215)),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(12, 8, 12, 8),
            Margin = new Thickness(0, 6, 0, 10)
        };
        RenderBlockChildren(node, section.Blocks);
        return section;
    }

    private Section RenderFigure(HtmlNode node)
    {
        var section = new Section
        {
            Margin = new Thickness(0, 12, 0, 16),
            TextAlignment = TextAlignment.Center
        };
        RenderBlockChildren(node, section.Blocks);
        return section;
    }

    private Section? RenderContainer(HtmlNode node, CssProperties style)
    {
        var section = new Section { Margin = new Thickness(0) };
        ApplyStyleToSection(section, style);
        RenderBlockChildren(node, section.Blocks);
        return section.Blocks.Count > 0 ? section : null;
    }

    private IEnumerable<Inline> RenderInlineChildren(HtmlNode node)
    {
        foreach (var child in node.ChildNodes)
            foreach (var inline in RenderInlines(child))
                yield return inline;
    }

    private IEnumerable<Inline> RenderInlines(HtmlNode node)
    {
        if (node.NodeType == HtmlNodeType.Text)
        {
            var text = HtmlEntity.DeEntitize(node.InnerText);
            if (string.IsNullOrEmpty(text)) yield break;
            // Normalize whitespace outside pre tags
            text = System.Text.RegularExpressions.Regex.Replace(text, @"[\r\n\t ]+", " ");
            if (!string.IsNullOrEmpty(text)) yield return new Run(text);
            yield break;
        }

        if (node.NodeType != HtmlNodeType.Element) yield break;

        var tag = node.Name.ToLower();
        var style = GetNodeStyle(node);

        // If this is a block element showing up inline, yield a LineBreak then recurse
        if (IsBlockElement(node) && tag != "br")
        {
            yield return new LineBreak();
            foreach (var child in node.ChildNodes)
                foreach (var i in RenderInlines(child))
                    yield return i;
            yield return new LineBreak();
            yield break;
        }

        switch (tag)
        {
            case "br":
                yield return new LineBreak();
                break;

            case "a":
            {
                var href = node.GetAttributeValue("href", "").Trim();
                if (string.IsNullOrEmpty(href) || href.StartsWith("javascript:"))
                {
                    foreach (var i in RenderStyledSpan(node, style)) yield return i;
                    break;
                }

                var resolved = DomReader.ResolveUrl(_baseUrl, href);
                var link = new Hyperlink
                {
                    Foreground = new SolidColorBrush(_darkMode ? Color.FromRgb(130, 180, 255) : Color.FromRgb(40, 100, 220)),
                    TextDecorations = TextDecorations.Underline
                };
                link.Click += (_, _) => _navigate?.Invoke(resolved);
                link.ToolTip = resolved;

                foreach (var inline in RenderInlineChildren(node)) link.Inlines.Add(inline);
                if (link.Inlines.Count == 0) link.Inlines.Add(new Run(href));
                yield return link;
                break;
            }

            case "strong" or "b":
            {
                var bold = new Bold();
                if (style.Color.HasValue) bold.Foreground = new SolidColorBrush(style.Color.Value);
                foreach (var inline in RenderInlineChildren(node)) bold.Inlines.Add(inline);
                yield return bold;
                break;
            }

            case "em" or "i":
            {
                var italic = new Italic();
                if (style.Color.HasValue) italic.Foreground = new SolidColorBrush(style.Color.Value);
                foreach (var inline in RenderInlineChildren(node)) italic.Inlines.Add(inline);
                yield return italic;
                break;
            }

            case "u" or "ins":
            {
                var underline = new Underline();
                foreach (var inline in RenderInlineChildren(node)) underline.Inlines.Add(inline);
                yield return underline;
                break;
            }

            case "s" or "strike" or "del":
            {
                var span = new Span();
                span.TextDecorations = TextDecorations.Strikethrough;
                span.Foreground = new SolidColorBrush(_darkMode ? Color.FromRgb(150, 150, 160) : Color.FromRgb(130, 130, 140));
                foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
                yield return span;
                break;
            }

            case "code" or "kbd" or "samp" or "tt":
            {
                var span = new Span
                {
                    FontFamily = new FontFamily("Consolas, Cascadia Code, Courier New"),
                    FontSize = 12,
                    Background = new SolidColorBrush(_darkMode ? Color.FromRgb(40, 42, 58) : Color.FromRgb(240, 240, 248)),
                    Foreground = new SolidColorBrush(_darkMode ? Color.FromRgb(200, 160, 255) : Color.FromRgb(160, 30, 180))
                };
                foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
                yield return span;
                break;
            }

            case "mark":
            {
                var span = new Span
                {
                    Background = new SolidColorBrush(Color.FromRgb(255, 235, 80)),
                    Foreground = new SolidColorBrush(Colors.Black)
                };
                foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
                yield return span;
                break;
            }

            case "abbr" or "acronym":
            {
                var span = new Span
                {
                    TextDecorations = TextDecorations.Underline,
                    Foreground = new SolidColorBrush(_darkMode ? Color.FromRgb(160, 220, 255) : Color.FromRgb(0, 100, 180))
                };
                span.ToolTip = node.GetAttributeValue("title", "");
                foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
                yield return span;
                break;
            }

            case "small":
            {
                var span = new Span { FontSize = 11 };
                foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
                yield return span;
                break;
            }

            case "sup":
            {
                var span = new Span { BaselineAlignment = BaselineAlignment.Superscript, FontSize = 10 };
                foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
                yield return span;
                break;
            }

            case "sub":
            {
                var span = new Span { BaselineAlignment = BaselineAlignment.Subscript, FontSize = 10 };
                foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
                yield return span;
                break;
            }

            case "img":
            {
                var alt = node.GetAttributeValue("alt", "");
                var src = node.GetAttributeValue("src", "");
                var placeholder = new Border
                {
                    Background = new SolidColorBrush(_darkMode ? Color.FromRgb(40, 45, 60) : Color.FromRgb(245, 245, 248)),
                    BorderBrush = new SolidColorBrush(_darkMode ? Color.FromRgb(60, 65, 80) : Color.FromRgb(210, 210, 220)),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(3),
                    Padding = new Thickness(8, 4, 8, 4)
                };
                var imgText = new TextBlock
                {
                    Text = $"🖼 {(string.IsNullOrEmpty(alt) ? "Image" : alt)}",
                    Foreground = new SolidColorBrush(_darkMode ? Color.FromRgb(150, 150, 170) : Color.FromRgb(120, 120, 135)),
                    FontSize = 11,
                    FontStyle = FontStyles.Italic
                };
                placeholder.Child = imgText;
                yield return new InlineUIContainer(placeholder) { BaselineAlignment = BaselineAlignment.Center };
                break;
            }

            case "span" or "label" or "time" or "cite" or "q" or "var" or "dfn":
            {
                foreach (var inline in RenderStyledSpan(node, style)) yield return inline;
                break;
            }

            default:
            {
                foreach (var inline in RenderInlineChildren(node)) yield return inline;
                break;
            }
        }
    }

    private IEnumerable<Inline> RenderStyledSpan(HtmlNode node, CssProperties style)
    {
        var span = new Span();
        ApplyStyleToSpan(span, style);
        foreach (var inline in RenderInlineChildren(node)) span.Inlines.Add(inline);
        yield return span;
    }

    private CssProperties GetNodeStyle(HtmlNode node)
    {
        var inline = node.GetAttributeValue("style", "");
        var props = CssEngine.ParseInlineStyle(inline);

        // Look up class-based styles
        var classes = node.GetAttributeValue("class", "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var cls in classes)
        {
            if (_stylesheet.TryGetValue("." + cls, out var classProps))
                MergeStyle(props, classProps);
        }

        // Tag-level style
        if (_stylesheet.TryGetValue(node.Name.ToLower(), out var tagProps))
            MergeStyle(props, tagProps);

        return props;
    }

    private static void MergeStyle(CssProperties target, CssProperties source)
    {
        target.Color ??= source.Color;
        target.BackgroundColor ??= source.BackgroundColor;
        target.FontSize ??= source.FontSize;
        target.Bold ??= source.Bold;
        target.Italic ??= source.Italic;
        target.Underline ??= source.Underline;
        target.FontFamily ??= source.FontFamily;
        target.TextAlign ??= source.TextAlign;
    }

    private void ApplyStyleToParagraph(Paragraph para, CssProperties style)
    {
        if (style.Color.HasValue)
            para.Foreground = new SolidColorBrush(style.Color.Value);
        if (style.BackgroundColor.HasValue)
            para.Background = new SolidColorBrush(style.BackgroundColor.Value);
        if (style.FontSize.HasValue)
            para.FontSize = style.FontSize.Value;
        if (style.Bold == true) para.FontWeight = FontWeights.Bold;
        if (style.Italic == true) para.FontStyle = FontStyles.Italic;
        if (style.TextAlign != null)
        {
            para.TextAlignment = style.TextAlign.ToLower() switch
            {
                "center" => TextAlignment.Center,
                "right" => TextAlignment.Right,
                "justify" => TextAlignment.Justify,
                _ => TextAlignment.Left
            };
        }
    }

    private void ApplyStyleToSection(Section section, CssProperties style)
    {
        if (style.BackgroundColor.HasValue)
            section.Background = new SolidColorBrush(style.BackgroundColor.Value);
    }

    private void ApplyStyleToSpan(Span span, CssProperties style)
    {
        if (style.Color.HasValue) span.Foreground = new SolidColorBrush(style.Color.Value);
        if (style.BackgroundColor.HasValue) span.Background = new SolidColorBrush(style.BackgroundColor.Value);
        if (style.FontSize.HasValue) span.FontSize = style.FontSize.Value;
        if (style.Bold == true) span.FontWeight = FontWeights.Bold;
        if (style.Italic == true) span.FontStyle = FontStyles.Italic;
        if (style.Underline == true) span.TextDecorations = TextDecorations.Underline;
        if (style.Strikethrough == true) span.TextDecorations = TextDecorations.Strikethrough;
        if (style.FontFamily != null) span.FontFamily = new FontFamily(style.FontFamily);
    }
}
